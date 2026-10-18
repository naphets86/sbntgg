# sbntgg

sbntgg teilt einen zugewiesenen IPv4- oder IPv6-Adressbereich automatisch in überlappungsfreie Subnetze für Mitarbeiter- und Ressourcengruppen auf (inklusive VLAN-IDs, Gateways und Wachstumsreserve) und erzeugt aus der Zugriffsmatrix optional Firewall-Regeln für iptables, nftables und Cisco-ACLs.

## Inhaltsverzeichnis

- [Überblick](#überblick)
- [Schnellstart](#schnellstart)
- [Konfiguration](#konfiguration)
- [Beispielkonfiguration](#beispielkonfiguration)
- [Berechnungsregeln](#berechnungsregeln)
- [Ausgabe](#ausgabe)
- [Firewall-Regeln](#firewall-regeln)
- [Projektstruktur](#projektstruktur)
- [Voraussetzungen](#voraussetzungen)
- [Installation](#installation)
- [Tests](#tests)
- [Erwerb](#erwerb)

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

Die Konfiguration ist eine YAML- oder JSON-Datei. Ein vollständiges Beispiel mit Erklärung steht im Abschnitt [Beispielkonfiguration](#beispielkonfiguration).

| Schlüssel | Bedeutung | Standard |
| --- | --- | --- |
| `base_network` | zugewiesener Bereich, zum Beispiel `10.20.0.0/16` | Pflicht |
| `growth_factor` | Wachstumsreserve je Gruppe, mindestens `1.0` | `1.25` |
| `allocation_strategy` | `vlsm` oder `fixed` | `vlsm` |
| `gateway_position` | `first`, `last` oder `none` | `first` |
| `groups` | Liste der Gruppen | Pflicht |

Je Gruppe: `name` und `hosts` sind Pflicht, `vlan_id`, `priority` und `access` sind optional. Die Optionen `--base-network`, `--growth-factor`, `--strategy` und `--gateway` überschreiben die Datei.

Gruppennamen dürfen nur Buchstaben, Ziffern, `_`, `-` und Leerzeichen enthalten, weil sie in Regelkommentaren und ACL-Namen landen.

## Beispielkonfiguration

Der Ordner `examples/` enthält mit `config.example.yaml` eine vollständige, sofort lauffähige Konfiguration für ein fiktives Firmennetz. Die Datei hat drei Aufgaben:

- **Vorlage:** Du kopierst sie und ersetzt Basisnetz und Gruppen durch die eigenen.
- **Referenz:** Sie verwendet jeden Konfigurationsschlüssel mindestens einmal und zeigt damit, wie die Schlüssel zusammenspielen.
- **Testgrundlage:** Der Test `test_example_configuration_is_valid` in `tests/test_cli.py` lädt die Datei, berechnet daraus einen Plan und prüft, dass fünf Subnetze entstehen und die Gruppe `Server` die VLAN-ID 100 erhält. Ändert sich später die Validierung, fällt eine veraltete Beispieldatei dadurch sofort auf.

### Inhalt der Datei

```yaml
# Beispielkonfiguration für subnetplan
base_network: 10.20.0.0/16      # zugewiesener Bereich (IPv4 oder IPv6)
growth_factor: 1.25             # Wachstumsreserve pro Gruppe (>= 1.0)
allocation_strategy: vlsm       # vlsm = größte Gruppe zuerst | fixed = einheitliche Präfixlänge
gateway_position: first         # first | last | none

groups:
  - name: Server
    hosts: 40
    vlan_id: 100
    priority: 0                 # kleinere Zahl = früher im Adressraum (bei gleicher Größe bzw. bei fixed)
    access: [Drucker]

  - name: Entwicklung
    hosts: 120
    access: [Server, Drucker]

  - name: HR
    hosts: 25
    access: [Drucker]

  - name: Drucker
    hosts: 12

  - name: Gäste
    hosts: 60                   # kein access: keine internen Ziele
```

### Das Szenario

Die Firma hat ein zugewiesenes Netz `10.20.0.0/16` und fünf Gruppen mit unterschiedlichen Rechten:

| Gruppe | Hosts | darf zugreifen auf | Besonderheit |
| --- | --- | --- | --- |
| `Server` | 40 | `Drucker` | feste `vlan_id: 100`, ausdrücklich `priority: 0` |
| `Entwicklung` | 120 | `Server`, `Drucker` | größte Gruppe, zwei Zugriffsziele |
| `HR` | 25 | `Drucker` | |
| `Drucker` | 12 | niemanden | reiner Dienst, löst selbst keine Verbindungen aus |
| `Gäste` | 60 | niemanden | kein `access`, also kein Zugriff auf interne Netze |

Damit zeigt die Datei die wichtigsten Fälle: eine explizit gesetzte VLAN-ID neben automatisch vergebenen, Gruppen mit mehreren, einem und keinem Zugriffsziel sowie die Felder `priority` und `access`. Die Kopfschlüssel `growth_factor`, `allocation_strategy` und `gateway_position` stehen mit ihren Standardwerten in der Datei, damit man sieht, was sich ändern lässt. `base_network` ist als Einziger ein Pflichtfeld ohne Standardwert.

### Was daraus berechnet wird

Der Aufruf

```bash
subnetplan examples/config.example.yaml
```

rechnet zuerst den Bedarf je Gruppe aus (Hosts mal 1,25, aufgerundet, plus Netzadresse, Broadcast und Gateway) und wählt die kleinste Präfixlänge, die diesen Bedarf fasst:

| Gruppe | Rechnung | Adressen | Präfix |
| --- | --- | --- | --- |
| `Entwicklung` | 120 × 1,25 = 150, plus 3 | 153 | `/24` (256) |
| `Gäste` | 60 × 1,25 = 75, plus 3 | 78 | `/25` (128) |
| `Server` | 40 × 1,25 = 50, plus 3 | 53 | `/26` (64) |
| `HR` | 25 × 1,25 = 31,25, aufgerundet 32, plus 3 | 35 | `/26` (64) |
| `Drucker` | 12 × 1,25 = 15, plus 3 | 18 | `/27` (32) |

Daraus entsteht dieser Plan (Auszug der Tabellenspalten):

| Gruppe | VLAN | Netz/CIDR | Gateway | Host-Range | Nutzbar | Bedarf |
| --- | --- | --- | --- | --- | --- | --- |
| `Entwicklung` | 10 | `10.20.0.0/24` | `10.20.0.1` | `10.20.0.2 - 10.20.0.254` | 253 | 120 |
| `Gäste` | 40 | `10.20.1.0/25` | `10.20.1.1` | `10.20.1.2 - 10.20.1.126` | 125 | 60 |
| `Server` | 100 | `10.20.1.128/26` | `10.20.1.129` | `10.20.1.130 - 10.20.1.190` | 61 | 40 |
| `HR` | 20 | `10.20.1.192/26` | `10.20.1.193` | `10.20.1.194 - 10.20.1.254` | 61 | 25 |
| `Drucker` | 30 | `10.20.2.0/27` | `10.20.2.1` | `10.20.2.2 - 10.20.2.30` | 29 | 12 |

Belegt sind 544 von 65.536 Adressen (0,83 %). Die 64.992 freien Adressen stehen als zehn zusammengefasste Restbereiche zur Verfügung, von `10.20.2.32/27` bis `10.20.128.0/17`. Dort lassen sich später weitere Gruppen anlegen, ohne bestehende Subnetze zu verschieben.

Drei Punkte erklärt das Beispiel besonders gut:

- **Reihenfolge im Adressraum:** `Gäste` steht in der Datei zuletzt, bekommt aber den zweiten Platz, weil `vlsm` die größten Blöcke zuerst vergibt und ein `/25` größer ist als `/26` und `/27`.
- **Gleiche Größe, gleiche Priorität:** `Server` und `HR` brauchen beide ein `/26` und haben `priority: 0` (bei `HR` der Standardwert). Dann entscheidet die Reihenfolge in der Datei, deshalb liegt `Server` vor `HR`. Setzt du bei `Server` eine größere Zahl als bei `HR` (zum Beispiel `priority: 1`), rückt `HR` nach vorn, denn die kleinere Zahl kommt zuerst.
- **VLAN-IDs:** `Server` behält die feste ID 100. Die übrigen Gruppen erhalten in Dateireihenfolge automatisch 10, 20, 30 und 40, also `Entwicklung` 10, `HR` 20, `Drucker` 30 und `Gäste` 40.

Die Spalte „Nutzbar“ liegt immer über dem Bedarf, weil Subnetzgrößen Zweierpotenzen sind. `Entwicklung` bekommt 253 nutzbare Adressen für 120 Hosts; der Rest ist die eingerechnete Wachstumsreserve.

### Firewall-Regeln aus dem Beispiel

```bash
subnetplan examples/config.example.yaml --firewall nftables --firewall-output rules.nft
```

Aus den `access`-Einträgen ergeben sich genau vier Freigaben: `Entwicklung` zu `Server`, `Entwicklung` zu `Drucker`, `Server` zu `Drucker` und `HR` zu `Drucker`. Der nftables-Teil der Ausgabe sieht so aus:

```text
table inet subnet_acl {
    chain forward {
        type filter hook forward priority 0; policy drop;
        ct state established,related accept
        ip saddr 10.20.0.0/24 ip daddr 10.20.1.128/26 accept comment "Entwicklung -> Server"
        ip saddr 10.20.0.0/24 ip daddr 10.20.2.0/27 accept comment "Entwicklung -> Drucker"
        ip saddr 10.20.1.128/26 ip daddr 10.20.2.0/27 accept comment "Server -> Drucker"
        ip saddr 10.20.1.192/26 ip daddr 10.20.2.0/27 accept comment "HR -> Drucker"
    }
}
```

`Drucker` und `Gäste` tauchen nie als Quelle auf. `Drucker` können Antworten auf Anfragen schicken (`ct state established,related`), aber keine eigenen Verbindungen in andere Netze aufbauen. `Gäste` erreichen keines der internen Netze.

Wichtig: Die erzeugten Regeln verwerfen alles, was nicht ausdrücklich freigegeben ist, also auch die Weiterleitung ins Internet. Brauchen `Gäste` Internetzugang, muss er zusätzlich im Regelwerk ergänzt werden.

Mit `--firewall iptables` entstehen dieselben vier Freigaben als `iptables`-Befehle in der Kette `SUBNET_ACL`. Mit `--firewall cisco` erhält jede Gruppe eine eigene eingehende ACL, zum Beispiel `ACL-100-SERVER` für `Server` am Interface `Vlan100`. Die ACL von `Gäste` (`ACL-40-GÄSTE`) enthält nur `deny ip any any`.

### Varianten ausprobieren

Die Beispieldatei lässt sich mit Kommandozeilenoptionen abwandeln, ohne sie zu bearbeiten:

```bash
# Alle Gruppen bekommen die Größe der größten Gruppe: fünf Netze 10.20.0.0/24 bis 10.20.4.0/24
subnetplan examples/config.example.yaml --strategy fixed

# Dasselbe Beispiel in einem anderen Adressbereich
subnetplan examples/config.example.yaml --base-network 192.168.0.0/16

# Ohne Wachstumsreserve und ohne Gateway-Adresse: kleinere Subnetze
subnetplan examples/config.example.yaml --growth-factor 1.0 --gateway none

# Maschinenlesbar weiterverarbeiten
subnetplan examples/config.example.yaml --format json -o plan.json
```

Bei `--strategy fixed` richtet sich die Reihenfolge nach `priority` und danach nach der Datei. Im Beispiel bekommt `Server` deshalb `10.20.0.0/24`, gefolgt von `Entwicklung`, `HR`, `Drucker` und `Gäste`.

### Eigene Konfiguration ableiten

1. Datei kopieren, zum Beispiel `cp examples/config.example.yaml mein-netz.yaml`.
2. `base_network` auf den zugewiesenen Bereich setzen.
3. Unter `groups` die eigenen Gruppen mit `name` und `hosts` eintragen, bei Bedarf `vlan_id` und `priority` ergänzen.
4. In `access` festlegen, welche Gruppen welche anderen erreichen dürfen. Die Namen müssen genau einer Gruppe in der Datei entsprechen.
5. `subnetplan mein-netz.yaml` ausführen. Tippfehler bei Schlüsseln, doppelte Namen oder VLAN-IDs, unbekannte Gruppen in `access` und zu wenig Platz im Basisnetz werden mit einer Fehlermeldung gemeldet, ohne dass ein Plan ausgegeben wird.

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
| `examples/` | Beispielkonfiguration `config.example.yaml` (fünf Gruppen), ausführlich beschrieben im Abschnitt [Beispielkonfiguration](#beispielkonfiguration) |
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

## Erwerb

Der Preis für diese Software beträgt 1.456.789,00 EUR

### Zahlungsinformationen

Name: Stephan Epp  
IBAN: DE24 5003 1900 0012 5603 20  
BIC: BBVADEFFXXX
