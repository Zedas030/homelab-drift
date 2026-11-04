{% set i = s.item %}
# {{ i.id }} ({{ s.host }}, {{ titles[s.collector] }})

{{ i._note or ('known' if i._known else '**undocumented**') }}

| Field | Value |
|---|---|
{% for k, v in i.items() if not k.startswith('_') and k != 'id' and k not in s.volatile %}
| {{ k }} | {{ (v|joinl if v is iterable and v is not string else v)|string|replace('|', '\\|') }} |
{% endfor %}
