"""Base-image resolution, fetching, and checksum verification."""

from __future__ import annotations

import os
from pathlib import Path
from urllib.parse import unquote, urlparse

from loguru import logger

from ..commands import CommandManager
from ..config import (
    DEFAULT_UBUNTU_NOBLE_IMG_URL,
    DEPRECATED_IMAGE_URL_REPLACEMENTS,
    SUPPORTED_IMAGE_SHA256,
    AgentVMConfig,
)
from ..errors import AIVMError
from ..privilege import path_needs_sudo, sudo_allowed
from ..util import CmdError
from .host_access import (
    _ensure_qemu_access,
    _sudo_file_exists,
    _undetermined_existence_error,
)
from .paths import _paths

log = logger


def _resolve_effective_image_url(image_url: str) -> str:
    """Return a retained supported URL for known obsolete built-in defaults."""
    requested = str(image_url or DEFAULT_UBUNTU_NOBLE_IMG_URL).strip()
    replacement = DEPRECATED_IMAGE_URL_REPLACEMENTS.get(requested)
    if replacement:
        log.warning(
            'Configured image URL points at an expired Ubuntu daily-build '
            'archive; using the retained release archive instead.\n'
            '  expired: {}\n'
            '  retained: {}',
            requested,
            replacement,
        )
        return replacement
    return requested


def _is_transfer_command_error(ex: CmdError) -> bool:
    """Return True when ``ex`` came from the image copy/download command."""
    cmd = [str(part) for part in ex.cmd] if not isinstance(ex.cmd, str) else []
    return any(Path(part).name in {'curl', 'cp'} for part in cmd)


def _image_transfer_failure_message(
    *, source: str, staging_path: Path, error: CmdError
) -> str:
    """Build an actionable error without obscuring the original command result."""
    source_label = 'URL' if urlparse(source).scheme != 'file' else 'Source'
    return (
        'Base image transfer failed. VM creation stopped before the staging '
        'file was promoted into the image cache.\n'
        f'{source_label}: {source}\n'
        f'Staging path: {staging_path}\n'
        f'Command exit code: {error.result.code}\n'
        'AIVM will remove any stale .part file before the next download attempt.'
    )


def _resolve_expected_image_sha256(*, image_url: str) -> tuple[str | None, str]:
    digest = SUPPORTED_IMAGE_SHA256.get(image_url, '').strip().lower()
    if digest:
        return digest, 'built-in supported-image hash registry'
    parsed = urlparse(image_url)
    if parsed.scheme == 'file':
        file_path = Path(unquote(parsed.path))
        if not file_path.exists():
            raise AIVMError(
                'Local file image URL does not exist.\n'
                f'Requested URL: {image_url}\n'
                f'Path: {file_path}'
            )
        out = (
            CommandManager.current()
            .run(
                ['sha256sum', str(file_path)],
                check=True,
                capture=True,
            )
            .stdout
        )
        local_digest = out.strip().split()[0].lower() if out.strip() else ''
        for supported_url, supported_digest in SUPPORTED_IMAGE_SHA256.items():
            if local_digest == supported_digest.strip().lower():
                return (
                    local_digest,
                    'local file URL matched supported pinned image digest '
                    f'({supported_url})',
                )
        supported_hashes = '\n'.join(
            f'  - {u} :: {d}' for u, d in sorted(SUPPORTED_IMAGE_SHA256.items())
        )
        raise AIVMError(
            'Image file URL digest is not in the built-in verified image registry.\n'
            f'Requested URL: {image_url}\n'
            f'Path: {file_path}\n'
            f'Actual SHA256: {local_digest}\n'
            'Supported URL/hash entries:\n'
            f'{supported_hashes}\n'
            'This often means a partial/corrupt local cache file. Delete it and retry.'
        )
    supported = '\n'.join(f'  - {u}' for u in sorted(SUPPORTED_IMAGE_SHA256))
    raise AIVMError(
        'Image URL is not in the built-in verified image registry.\n'
        f'Requested URL: {image_url}\n'
        'Supported URLs:\n'
        f'{supported}\n'
        'Use a supported image URL, or add this URL + SHA256 to SUPPORTED_IMAGE_SHA256.'
    )


def _verify_image_sha256(
    *, image_path: Path, expected_sha256: str | None, source: str
) -> None:
    if not expected_sha256:
        return
    mgr = CommandManager.current()
    log.info('Verifying base image checksum (source: {})', source)
    # Cached images are usually world-readable, so sudo is only needed when
    # the current user cannot read the file directly.
    out = mgr.submit(
        ['sha256sum', str(image_path)],
        sudo=not os.access(image_path, os.R_OK) and sudo_allowed(),
        role='read',
        check=True,
        capture=True,
        summary='Compute base image checksum',
        detail=f'path={image_path} source={source}',
    ).stdout
    actual = out.strip().split()[0].lower() if out.strip() else ''
    if actual != expected_sha256:
        mgr.submit(
            ['rm', '-f', str(image_path)],
            sudo=path_needs_sudo(image_path),
            role='modify',
            check=False,
            capture=True,
            summary='Remove invalid base image after checksum mismatch',
            detail=f'path={image_path}',
        ).result()
        raise AIVMError(
            'Downloaded base image checksum mismatch; removed invalid image.\n'
            f'Path: {image_path}\n'
            f'Expected: {expected_sha256}\n'
            f'Actual:   {actual}\n'
            'Re-run to retry download, or use a supported pinned image URL.'
        )
    log.info('Base image checksum verified: {}', image_path)


def fetch_image(cfg: AgentVMConfig, *, dry_run: bool = False) -> Path:
    log.trace('fetch_image vm={} dry_run={}', cfg.vm.name, dry_run)
    log.debug('Fetching Ubuntu cloud image')
    p = _paths(cfg, dry_run=dry_run)
    base_img = p['img_dir'] / cfg.image.cache_name
    tmp_img = Path(str(base_img) + '.part')
    requested_url = cfg.image.ubuntu_img_url or DEFAULT_UBUNTU_NOBLE_IMG_URL
    url = _resolve_effective_image_url(requested_url)
    if url != requested_url:
        # Carry the compatibility repair forward when the VM record is saved.
        cfg.image.ubuntu_img_url = url
    expected_sha256, checksum_source = _resolve_expected_image_sha256(
        image_url=url
    )
    parsed = urlparse(url)
    local_file_src = (
        Path(unquote(parsed.path)).expanduser()
        if parsed.scheme == 'file'
        else None
    )
    mgr = CommandManager.current()
    base_img_cached = _sudo_file_exists(base_img)
    if base_img_cached is None:
        raise _undetermined_existence_error(base_img, 'cached base image')
    if base_img_cached and not cfg.image.redownload:
        if dry_run:
            log.info('Base image cached: {}', base_img)
            return base_img
        # Re-verify named cache hits so interrupted downloads or stale local
        # files do not silently poison later VM creation runs.
        try:
            with mgr.intent(
                'Fetch base image',
                why=(
                    'VM creation needs a verified Ubuntu cloud image cached on '
                    'the host before the VM disk can be prepared.'
                ),
                role='modify',
            ):
                with mgr.step(
                    'Verify cached base image',
                    why=(
                        'Revalidate the cached image so interrupted downloads or '
                        'stale local files do not silently poison later VM runs.'
                    ),
                    approval_scope=f'image-verify-cache:{cfg.vm.name}',
                ):
                    _verify_image_sha256(
                        image_path=base_img,
                        expected_sha256=expected_sha256,
                        source=f'cached base image ({checksum_source})',
                    )
            log.info('Base image cached: {}', base_img)
            return base_img
        except RuntimeError as ex:
            log.warning(
                'Cached base image failed checksum verification; redownloading. {}',
                ex,
            )
    if dry_run:
        if local_file_src is not None:
            log.info(
                'DRYRUN: cp {} {}; mv {} {}',
                local_file_src,
                tmp_img,
                tmp_img,
                base_img,
            )
        else:
            log.info(
                'DRYRUN: curl -L --fail -o {} {}; mv {} {}',
                tmp_img,
                url,
                tmp_img,
                base_img,
            )
        return base_img
    _ensure_qemu_access(cfg, dry_run=False)
    if local_file_src is not None:
        log.info(
            'Copying local base image to {} via atomic temp file', base_img
        )
    else:
        log.info('Downloading base image to {} (showing progress)', base_img)
    use_sudo = path_needs_sudo(p['img_dir'])
    with mgr.intent(
        'Fetch base image',
        why=(
            'VM creation needs a verified Ubuntu cloud image cached on the '
            'host before the VM disk can be prepared.'
        ),
        role='modify',
    ):
        try:
            with mgr.step(
                'Fetch and verify base image',
                why=(
                    'Prepare the image directory, refresh any stale partial file, '
                    'transfer the image atomically, and verify its checksum before '
                    'it is reused.'
                ),
                approval_scope=f'image-fetch:{cfg.vm.name}',
            ):
                mkdir_handle = mgr.submit(
                    ['mkdir', '-p', str(p['img_dir'])],
                    sudo=use_sudo,
                    role='modify',
                    check=True,
                    capture=True,
                    summary='Create VM image directory',
                    detail=f'target={p["img_dir"]}',
                )
                cleanup_tmp_handle = mgr.submit(
                    ['rm', '-f', str(tmp_img)],
                    sudo=use_sudo,
                    role='modify',
                    check=False,
                    capture=True,
                    summary='Remove stale partial image file',
                    detail=f'target={tmp_img}',
                )
                transfer_cmd = (
                    ['cp', '--reflink=auto', str(local_file_src), str(tmp_img)]
                    if local_file_src is not None
                    else [
                        'curl',
                        '-L',
                        '--fail',
                        '--progress-bar',
                        '-o',
                        str(tmp_img),
                        url,
                    ]
                )
                transfer_handle = mgr.submit(
                    transfer_cmd,
                    sudo=use_sudo,
                    role='modify',
                    check=True,
                    capture=(local_file_src is not None),
                    summary=(
                        'Copy local base image into staging file'
                        if local_file_src is not None
                        else 'Download base image into staging file'
                    ),
                    detail=(
                        f'source={local_file_src} destination={tmp_img}'
                        if local_file_src is not None
                        else f'url={url} destination={tmp_img}'
                    ),
                )
                move_handle = mgr.submit(
                    ['mv', '-f', str(tmp_img), str(base_img)],
                    sudo=use_sudo,
                    role='modify',
                    check=True,
                    capture=True,
                    summary='Move staged base image into cache',
                    detail=f'source={tmp_img} destination={base_img}',
                )
                checksum_handle = mgr.submit(
                    ['sha256sum', str(base_img)],
                    sudo=use_sudo,
                    role='read',
                    check=True,
                    capture=True,
                    summary='Compute base image checksum',
                    detail=f'path={base_img} source={checksum_source}',
                )
                mkdir_handle.result()
                cleanup_tmp_handle.result()
                transfer_handle.result()
                move_handle.result()
                checksum_out = checksum_handle.stdout
        except CmdError as ex:
            if _is_transfer_command_error(ex):
                raise AIVMError(
                    _image_transfer_failure_message(
                        source=url, staging_path=tmp_img, error=ex
                    )
                ) from ex
            raise
        actual = (
            checksum_out.strip().split()[0].lower()
            if checksum_out.strip()
            else ''
        )
        if expected_sha256 and actual != expected_sha256:
            mgr.submit(
                ['rm', '-f', str(base_img)],
                sudo=use_sudo,
                role='modify',
                check=False,
                capture=True,
                summary='Remove invalid base image after checksum mismatch',
                detail=f'path={base_img}',
            ).result()
            raise AIVMError(
                'Downloaded base image checksum mismatch; removed invalid image.\n'
                f'Path: {base_img}\n'
                f'Expected: {expected_sha256}\n'
                f'Actual:   {actual}\n'
                'Re-run to retry download, or use a supported pinned image URL.'
            )
        log.info('Base image checksum verified: {}', base_img)
    log.info('Downloaded base image: {}', base_img)
    return base_img
