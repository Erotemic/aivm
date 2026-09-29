repo="Erotemic/ambition"
agent_name="coding-agent-toothbrush"

key_dir="$HOME/.ssh/github-agents"
key_name="${repo//\//_}--${agent_name}"
key_path="$key_dir/$key_name"

install -d -m 700 "$key_dir"

if [[ ! -f "$key_path" ]]; then
    ssh-keygen \
        -q \
        -t ed25519 \
        -N "" \
        -C "deploy-key:${repo}:${agent_name}" \
        -f "$key_path"
fi

chmod 600 "$key_path"
chmod 644 "$key_path.pub"

gh repo deploy-key add "$key_path.pub" \
    --repo "$repo" \
    --title "$agent_name" \
    --allow-write

gh repo deploy-key list \
    --repo "$repo"
