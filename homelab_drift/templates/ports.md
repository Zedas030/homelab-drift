# Port overview

All listening ports on all hosts.

| Port | Host | Exposure | Service | Note |
|---|---|---|---|---|
{% for p in ports %}
| {{ (p.proto ~ ' ephemeral') if p.ephemeral else (p.port ~ '/' ~ p.proto) }} | {{ p.host }} | {{ p.exposure }} | {{ p._service }} | {{ p._note or ('known' if p._known else '**undocumented**') }} |
{% endfor %}
