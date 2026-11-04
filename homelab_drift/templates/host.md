{% macro n(i) %}{{ i._note or ('known' if i._known else '**undocumented**') }}{% endmacro %}
# {{ host.name }}

{{ host.description }}{% if host.note %} – _{{ host.note }}_{% endif %}

{% set sys = host.system %}
{% if sys.hostname %}
- Hostname: {{ sys.hostname }} (`{{ host.address }}`)
- System: {{ sys.os }}, kernel {{ sys.kernel }}, {{ sys.arch }}, {{ sys.cpus }} CPUs, {{ sys.mem_gb }} GB RAM
- Last boot: {{ sys.boot_time|ts }}
{% endif %}

{% for cname, c in host.cols.items() if cname != 'system' and c['items'] %}
## {{ titles[cname] }}

{% if cname == 'docker' %}
| Container | Image | Version | Status | Ports | Restart | Note |
|---|---|---|---|---|---|---|
{% for i in c['items'] %}
| [{{ i.id }}](services/{{ (host.name ~ '-docker-' ~ i.id)|slug }}.md) | `{{ i.image }}` | {{ i.version or i.image_id }} | {{ i.state }} | {{ i.ports|joinl }} | {{ i.restart_policy }} | {{ n(i) }} |
{% endfor %}
{% elif cname == 'ports' %}
| Port | Exposure | Service | Note |
|---|---|---|---|
{% for i in c['items'] %}
| {{ (i.proto ~ ' ephemeral') if i.ephemeral else (i.port ~ '/' ~ i.proto) }} | {{ i.exposure }} | {{ i._service }} | {{ n(i) }} |
{% endfor %}
{% elif cname == 'nginx' %}
| Site | listen | root / proxies | Note |
|---|---|---|---|
{% for i in c['items'] %}
| {{ i.id }} | {{ (i.listen or i.servers)|joinl }} | {{ i.root }} {{ i.proxies|joinl('; ') }} | {{ n(i) }} |
{% endfor %}
{% elif cname == 'cron' %}
| Schedule | User | Command | Source | Note |
|---|---|---|---|---|
{% for i in c['items'] %}
| `{{ i.schedule }}` | {{ i.user }} | `{{ i.command|replace('|', '\\|') }}` | {{ i.source }} | {{ n(i) }} |
{% endfor %}
{% elif cname == 'systemd' %}
| Unit | Status | User | Schedule / command | Note |
|---|---|---|---|---|
{% for i in c['items'] %}
| {{ i.id }} | {{ i.run_state }} ({{ i.unit_file_state }}) | {{ i.user }} | `{{ ((i.schedule ~ ' → ' ~ i.unit) if i.kind == 'timer' else i.exec[:120])|replace('|', '\\|') }}` | {{ n(i) }} |
{% endfor %}
{% elif cname == 'storage' %}
| Mount | Source | Type | Usage | Note |
|---|---|---|---|---|
{% for i in c['items'] %}
| `{{ i.id }}` | `{{ i.source }}` | {{ i.fstype }} | {{ i.level }} (size {{ i.size|bytes }}) | {{ n(i) }} |
{% endfor %}
{% elif cname == 'tailscale' %}
| Device | IPs | OS | Note |
|---|---|---|---|
{% for i in c['items'] %}
| {{ i.id }} | {{ i.ips|joinl }} | {{ i.os }} | {{ n(i) }} |
{% endfor %}
{% elif cname == 'fritzbox' %}
| Device | IP | MAC | Note |
|---|---|---|---|
{% for i in c['items'] %}
| {{ i.name }} | {{ i.ip }} | {{ i.id }} | {{ n(i) }} |
{% endfor %}
{% endif %}

{% endfor %}
