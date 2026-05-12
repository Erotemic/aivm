"""Base-image resolution, fetching, and checksum verification."""

from __future__ import annotations

from pathlib import Path
from urllib.parse import unquote, urlparse

from loguru import logger

from ..commands import CommandManager
from ..config import (
    DEFAULT_UBUNTU_NOBLE_IMG_URL,
    SUPPORTED_IMAGE_SHA256,
    AgentVMConfig,
)
from ..util import CmdError
from .host_access import _ensure_qemu_access, _sudo_file_exists
from .paths import _paths

log = logger

def _resolve_expected_image_sha256(*, image_url: str) -> tuple[str | None, str]:
    digest = SUPPORTED_IMAGE_SHA256.get(image_url, '').strip().lower()
    if digest:
        return digest, 'built-in supported-image hash registry'
    parsed = urlparse(image_url)
    if parsed.scheme == 'file':
        file_path = Path(unquote(parsed.path))
        if not file_path.exists():
            raise RuntimeError(
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
        raise RuntimeError(
            'Image file URL digest is not in the built-in verified image registry.\n'
            f'Requested URL: {image_url}\n'
            f'Path: {file_path}\n'
            f'Actual SHA256: {local_digest}\n'
            'Supported URL/hash entries:\n'
            f'{supported_hashes}\n'
            'This often means a partial/corrupt local cache file. Delete it and retry.'
        )
    supported = '\n'.join(f'  - {u}' for u in sorted(SUPPORTED_IMAGE_SHA256))
    raise RuntimeError(
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
    out = mgr.submit(
        ['sha256sum', str(image_path)],
        sudo=True,
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
            sudo=True,
            role='modify',
            check=False,
            capture=True,
            summary='Remove invalid base image after checksum mismatch',
            detail=f'path={image_path}',
        ).result()
        raise RuntimeError(
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
    url = cfg.image.ubuntu_img_url or DEFAULT_UBUNTU_NOBLE_IMG_URL
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
    if _sudo_file_exists(base_img) and not cfg.image.redownload:
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
    with mgr.intent(
        'Fetch base image',
        why=(
            'VM creation needs a verified Ubuntu cloud image cached on the '
            'host before the VM disk can be prepared.'
        ),
        role='modify',
    ):
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
                sudo=True,
                role='modify',
                check=True,
                capture=True,
                summary='Create VM image directory',
                detail=f'target={p["img_dir"]}',
            )
            cleanup_tmp_handle = mgr.submit(
                ['rm', '-f', str(tmp_img)],
                sudo=True,
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
                sudo=True,
                role='modify',
                check=False,
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
                sudo=True,
                role='modify',
                check=True,
                capture=True,
                summary='Move staged base image into cache',
                detail=f'source={tmp_img} destination={base_img}',
            )
            checksum_handle = mgr.submit(
                ['sha256sum', str(base_img)],
                sudo=True,
                role='read',
                check=True,
                capture=True,
                summary='Compute base image checksum',
                detail=f'path={base_img} source={checksum_source}',
            )
            mkdir_handle.result()
            cleanup_tmp_handle.result()
            transfer_res = transfer_handle.result()
            if transfer_res.code != 0:
                mgr.submit(
                    ['rm', '-f', str(tmp_img)],
                    sudo=True,
                    role='modify',
                    check=False,
                    capture=True,
                    summary='Remove incomplete staging image after transfer failure',
                    detail=f'target={tmp_img}',
                ).result()
                raise CmdError(transfer_cmd, transfer_res)
            move_handle.result()
            checksum_out = checksum_handle.stdout
            actual = (
                checksum_out.strip().split()[0].lower()
                if checksum_out.strip()
                else ''
            )
            if expected_sha256 and actual != expected_sha256:
                mgr.submit(
                    ['rm', '-f', str(base_img)],
                    sudo=True,
                    role='modify',
                    check=False,
                    capture=True,
                    summary='Remove invalid base image after checksum mismatch',
                    detail=f'path={base_img}',
                ).result()
                raise RuntimeError(
                    'Downloaded base image checksum mismatch; removed invalid image.\n'
                    f'Path: {base_img}\n'
                    f'Expected: {expected_sha256}\n'
                    f'Actual:   {actual}\n'
                    'Re-run to retry download, or use a supported pinned image URL.'
                )
            log.info('Base image checksum verified: {}', base_img)
    log.info('Downloaded base image: {}', base_img)
    return base_img
