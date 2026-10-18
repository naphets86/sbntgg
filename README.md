# sbntgg

## Inhaltsverzeichnis

- [Überblick](#überblick)
- [Schnellstart](#schnellstart)
- [Konfiguration](#konfiguration)
- [Berechnungsregeln](#berechnungsregeln)
- [Ausgabe](#ausgabe)
- [Firewall-Regeln](#firewall-regeln)
- [Projektstruktur](#projektstruktur)
- [Voraussetzungen](#voraussetzungen)
- [Installation](#installation)
- [Tests](#tests)

## Überblick

`subnetplan` teilt einen zugewiesenen IP-Bereich (IPv4 oder IPv6) automatisch in Subnetze für Mitarbeiter- und Ressourcengruppen auf. Jede Gruppe erhält ein eigenes Subnetz mit VLAN-ID, Gateway und Wachstumsreserve. Aus der Zugriffsmatrix (`access`) lassen sich optional Firewall-Regeln für iptables, nftables oder Cisco-ACLs erzeugen.

## Schnellstart

```bash
python -m venv .venv && source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -e ".[dev]"
subnetplan examples/config.example.yaml
```

Ohne Installation funktioniert auch `python -m src.cli examples/config.example.yaml`.

```bash
subnetplan examples/config.example.yaml --format json -o plan.json
subnetplan examples/config.example.yaml --format csv -o plan.csv
subnetplan examples/config.example.yaml --firewall nftables --firewall-output rules.nft
subnetplan examples/config.example.yaml --base-network 192.168.0.0/16 --strategy fixed
```

Mit `--format json` oder `--format csv` zusammen mit `--firewall` muss `--output` oder `--firewall-output` angegeben werden, damit die Standardausgabe maschinenlesbar bleibt.

## Konfiguration

Die Konfiguration ist eine YAML- oder JSON-Datei, siehe `examples/config.example.yaml`.

| Schlüssel | Bedeutung | Standard |
| --- | --- | --- |
| `base_network` | zugewiesener Bereich, zum Beispiel `10.20.0.0/16` | Pflicht |
| `growth_factor` | Wachstumsreserve je Gruppe, mindestens `1.0` | `1.25` |
| `allocation_strategy` | `vlsm` oder `fixed` | `vlsm` |
| `gateway_position` | `first`, `last` oder `none` | `first` |
| `groups` | Liste der Gruppen | Pflicht |

Je Gruppe: `name` und `hosts` sind Pflicht, `vlan_id`, `priority` und `access` sind optional. Die Optionen `--base-network`, `--growth-factor`, `--strategy` und `--gateway` überschreiben die Datei.

Gruppennamen dürfen nur Buchstaben, Ziffern, `_`, `-` und Leerzeichen enthalten, weil sie in Regelkommentaren und ACL-Namen landen.

## Berechnungsregeln

- Bedarf je Gruppe: `ceil(hosts * growth_factor)` plus Netzadresse, Broadcast (nur IPv4) und Gateway (außer bei `gateway_position: none`). Das Subnetz erhält die kleinste Präfixlänge, die diesen Bedarf fasst.
- `vlsm`: größte Blöcke zuerst, bei gleicher Größe entscheidet `priority` (kleinere Zahl zuerst), danach die Reihenfolge in der Konfiguration.
- `fixed`: alle Gruppen erhalten die Präfixlänge der größten Gruppe, die Reihenfolge folgt `priority` und danach der Konfiguration.
- Fehlt `vlan_id`, wird automatisch vergeben (10, 20, 30, ...), ohne Kollision mit expliziten IDs.
- Reicht das Basisnetz nicht aus, bricht `subnetplan` mit einer Meldung zum Platzmangel ab.

## Ausgabe

Tabelle (Standard), CSV oder JSON mit Gruppe, VLAN, Netz/CIDR, Subnetzmaske, Gateway, Host-Range, Broadcast, nutzbaren Hosts und angefordertem Bedarf. Dazu kommen Belegung des Basisnetzes und die freien Restbereiche.

## Firewall-Regeln

Alles, was nicht in `access` freigegeben ist, wird verworfen. Zugriff auf das eigene Subnetz braucht keine Regel.

| System | Ausgabe |
| --- | --- |
| `iptables` | eigene Kette `SUBNET_ACL` (zustandsbehaftet), eingehängt in `FORWARD`; `ip6tables` bei IPv6 |
| `nftables` | Tabelle `inet subnet_acl` mit Policy `drop`, zustandsbehaftet |
| `cisco` | je Gruppe eine eingehende Extended-ACL am Interface `Vlan<ID>` |

Cisco-ACLs sind zustandslos, Rückverkehr braucht passende Gegenregeln. Die erzeugten Regeln sind ein Ausgangspunkt und sollten vor dem Einspielen geprüft werden.

## Projektstruktur

| Pfad | Inhalt |
| --- | --- |
| `src/models.py` | Konstanten, Datenklassen, `PlanError` |
| `src/config.py` | Laden und Validieren der Konfiguration |
| `src/planner.py` | Bedarfsberechnung, VLAN-Vergabe, Subnetz-Zuteilung |
| `src/render.py` | Ausgabe als Tabelle, CSV und JSON |
| `src/firewall.py` | Regeln für iptables, nftables und Cisco |
| `src/cli.py` | Kommandozeile |
| `tests/` | pytest-Tests |
| `examples/` | Beispielkonfiguration |
| `doc/coverage/` | HTML-Bericht der Testabdeckung (wird beim Testlauf erzeugt) |
| `pyproject.toml` | Projektmetadaten sowie pytest- und Coverage-Konfiguration |

## Voraussetzungen

- Python 3.11 oder neuer
- PyYAML
- Für Tests: `pytest` und `pytest-cov`

## Installation

```bash
python -m venv .venv
source .venv/bin/activate   # Windows: .venv\Scripts\activate
pip install -e ".[dev]"
```

## Tests

```bash
pytest
```

Die Konfiguration in `pyproject.toml` setzt `tests` als Testverzeichnis, `.` und `src` als Importpfade und erzeugt einen Coverage-Bericht mit Zweigabdeckung im Terminal sowie als HTML unter `doc/coverage/`.

## Lizenz und Erwerb

Die Software wird als kommerzielle App für den privaten Sideload-Betrieb vertrieben.

### Preis

1.456.789,00 EUR

### Zahlungsinformationen

Name: Stephan Epp  
IBAN: DE24 5003 1900 0012 5603 20  
BIC: BBVADEFFXXX
