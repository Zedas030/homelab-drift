# Changelog

Generated automatically by Homelab-Drift. Newest entries first.

{% set ns = namespace(day='') %}
{% for e in changelog %}
{% if e.ts[:10] != ns.day %}
{% set ns.day = e.ts[:10] %}

## {{ ns.day|day }}

{% endif %}
- {{ e.ts[11:16] }} · **{{ e.host }}** · {{ e.summary }}{% if e.finding %} ({{ e.finding }}{{ ', acknowledged' if e.status == 'acknowledged' }}){% endif %}
{% endfor %}
