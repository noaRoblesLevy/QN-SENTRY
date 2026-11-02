# QN-Sentry — presentatie (verdediging 10/11/2026)

Spreekscript en stand van zaken voor de verdediging (±15 min + vragen).

- **Deck in deze map:** `qn-sentry-presentatie.pptx` (PowerPoint)
- **Demoscenario (bron, tijdstip per tijdstip):** [`../project/11-demo-scenario.md`](../project/11-demo-scenario.md)

> Let op: de huidige PPTX is een **tussenstand met placeholders** (`[__]` op de slides Automatisatie en Resultaat). Na de eindscan opnieuw exporteren en dit bestand vervangen.

## Opbouw (15 minuten)

| # | Slide | Spreker | Tijd |
|---|---|---|---|
| 1 | Cover | Quinten | 0:00–0:20 |
| 2 | Probleem | Quinten → Noa | 0:20–1:30 |
| 3 | Concept (4 stappen) | Noa | 1:30–2:15 |
| 4 | Modules | Noa | 2:15–3:00 |
| 5 | Demo (naar dashboard) | samen | 3:00–9:00 |
| 6 | Architectuur | Quinten | 9:00–10:15 |
| 7 | Automatisatie & kwaliteit | Quinten | 10:15–11:30 |
| 8 | Keuzes & verantwoording | Noa | 11:30–13:30 |
| 9 | Resultaat | samen | 13:30–14:15 |
| 10 | Reflectie | ieder een stuk | 14:15–14:45 |
| 11 | Slot — Vragen? | samen | 14:45–15:00 |

## Nog te doen vóór indienen (zie ook onderaan per slide)

- [ ] **Eindscan draaien** op `badsecurityinc.be` en de cijfers invullen: testaantal (slide 7) en detectiegraad + precisie (slide 9).
- [ ] **Reflectie personaliseren** (slide 10): ieder vult de `[...]`-regels in met een eigen, concreet voorbeeld.
- [ ] **PHP2Shell-moment checken** (demo 4:30): toont de scan van de Vercel-site die bevinding echt? Zo niet, dit moment uit de demo halen en in de conclusie zetten als "wat de tool kan".
- [ ] **Demo-data verifiëren** met de eindscan: `jan.peeters` met wachtwoord, interne pad `SRV-FS01`, gebruikersnaam `ljanssens`, certificaat voor de lookalike.
- [ ] **Backup-filmpje** van de demo opnemen (los `.mp4`-bestand om af te spelen als het netwerk of de laptop hapert).
- [ ] **Rolverdeling tijdens de demo** vastleggen: wie klikt, wie praat.
- [ ] **Repeteren met timer** (minstens 2x volledig) en de timings bijstellen.
- [ ] Na de eindscan: deck opnieuw exporteren en `qn-sentry-presentatie.pptx` vervangen; ook op Google Drive en Canvas zetten.

---

## Spreekscript per slide

### 1. Cover — *Quinten*
> "Goeiemiddag, wij zijn Quinten en Noa, en dit is QN-Sentry. Stel: je bent een kleine Belgische kmo. Twintig man, een website, wat documenten online. Je denkt: wie zou ons nu interessant vinden?"

Daarna doorklikken naar de probleemslide.

### 2. Probleem — *Noa, brugzin Quinten*
> **Noa:** "Het punt is: een aanvaller begint niet met inbreken, hij begint met kijken. Publieke documenten, DNS-gegevens, oude datalekken — allemaal legaal op te vragen, zonder dat het bedrijf er iets van merkt. Tegen dat een kmo doorheeft dat ze een doelwit is, heeft de aanvaller zijn huiswerk al gemaakt."
>
> **Quinten:** "Wat als die kmo datzelfde huiswerk zelf kon zien? Dat is QN-Sentry: één domein erin, en je ziet je eigen bedrijf door de ogen van een aanvaller."

### 3. Concept — *Noa*
> "QN-Sentry werkt bewust niet-intrusief. Het valt niets aan, het kijkt alleen — net als een aanvaller in zijn verkenningsfase. Je geeft één ding: het domein van het bedrijf. Daarna draaien vier modules, en het resultaat is één risicoscore en een rapport dat een zaakvoerder meteen begrijpt."

### 4. Modules — *Noa*
> "Die vier modules dekken elk een hoek af. Aanvalsoppervlak: welke servers en poorten staan open. Documentmetadata: wat lekt er uit publieke bestanden, zoals interne paden en gebruikersnamen. Phishing: bestaan er lookalike-domeinen, en is de e-mailbeveiliging in orde. En datalekken: staan er bedrijfsadressen met een gelekt wachtwoord online. Elke module levert bevindingen in één vast formaat."
>
> **Brugzin:** "Genoeg uitleg — laten we het tonen op ons eigen testbedrijf."

### 5. Demo — *samen* (draaiboek ±6 min)
Overschakelen naar het dashboard. Backup: filmpje afspelen als iets hapert.

| Tijd | Scherm | Wat zeggen |
|---|---|---|
| 0:00 | Clients + formulier | "Dit is alles wat een MSP ingeeft: een bedrijfsnaam en een domein." |
| 0:30 | Scan starten | "De API zet de scan in de wachtrij; een worker draait de vier modules op de achtergrond." |
| 1:00 | Ochtendscan openen | "Terwijl die draait, lopen we door dezelfde scan van vanmorgen." |
| 1:15 | Risicoscore | "Eén getal voor de zaakvoerder. Het sterretje betekent: scan met een verwachte waarschuwing, dus niet volledig." |
| 1:45 | Metadata | "Publieke documenten lekken het interne pad SRV-FS01, de gebruikersnaam ljanssens en oude Office-versies." |
| 2:30 | Phishing lookalike + certificaat | "Een l in plaats van een i, met een mailserver en een geldig certificaat." |
| 3:15 | SPF +all / DMARC p=none | "Het echte domein laat iedereen mail versturen in hun naam." |
| 3:45 | Breach | "jan.peeters met een gelekt wachtwoord. We bewaren alleen de naam van het lek en het type data, nooit het wachtwoord zelf (GDPR)." |
| 4:30 | Attack Surface + PHP2Shell | "De www-webservice en het poortscan-paneel; het Vercel-adres staat bewust niet goedgekeurd. [Wauw-moment: toon de PHP2Shell-bevinding — zie TODO.]" |
| 5:00 | PDF-rapport | "Dezelfde risicoscore als op het scherm, in een rapport voor de zaakvoerder." |
| 5:30 | Live scan klaar | "Zelfde resultaten als de ochtendscan — dit bewijst dat niets vooraf geregisseerd was." |

### 6. Architectuur — *Quinten*
> "Onder de motorkap is het bewust eenvoudig gehouden. Het dashboard praat met een API, die een scan in een wachtrij zet. Een aparte worker pikt die op en draait de vier modules één voor één. Zo blijft het dashboard altijd vlot, ook tijdens een zware scan. Alles draait in Docker-containers, lokaal, zodat de scandata op de machine van de klant blijft."

### 7. Automatisatie & kwaliteit — *Quinten*
> "We hebben sterk op herbruikbaarheid ingezet. Eén commando, install.sh, controleert Docker, genereert de geheimen en start alles — een medestudent heeft het in tien minuten draaiend. Elke wijziging gaat door automatische tests: unit tests, een migratiecheck en zelfs een installatietest op een propere machine. En alle modules leveren hun bevindingen in één vast formaat, zodat het dashboard, het rapport en de risicoscore nooit modulespecifieke code nodig hebben."

- **TODO:** exacte testaantal bevestigen na de eindscan (nu "± 450" op de slide).

### 8. Keuzes & verantwoording — *Noa*
> "Een paar keuzes willen we uitlichten. Eén: het platform gaat nooit online. Scandata is gevoelig, dus alles draait lokaal bij de klant; login met rollen is bewust toekomstwerk. Twee: we hebben geen test-VM online gezet, omdat we geen cloud-credits meer hadden. De poortscan is wél gebouwd en getest tegen een decoy, maar we hebben ze niet live kunnen meten — dat vermelden we eerlijk als beperking. Drie: scannen mag pas na expliciete goedkeuring per IP-adres. Een domein bewijst immers geen controle over de server erachter, en gedeelde hosting scannen we nooit."

### 9. Resultaat — *samen*
> "We sluiten af met cijfers, geen beloftes. Van de `[__]` meetbare geplante zwaktes vond de scan er `[__]`, met een precisie van `[__]` procent — dus nauwelijks vals alarm. De vier modules werken in één keten. Sterk vinden we de volledige, meetbare keten en de eerlijke scope; onze werkpunten zijn de live test-VM die er niet kwam en een login met rollen."

- **TODO:** `[__]`-cijfers invullen na de eindscan (detectiegraad, precisie).

### 10. Reflectie — *ieder een stuk*
Startpunten (maak ze je eigen, ieder één concreet voorbeeld):

- **Goed gegaan:** taakverdeling via GitHub-issues; één data contract hield de modules los testbaar; de keten werkte end-to-end.
- **Lastig:** scope bijsturen zonder cloud-credits; domeinverificatie via DNS betrouwbaar krijgen; `[eigen lastigste moment]`.
- **Volgende keer:** vroeger een testserver vastleggen los van gratis credits; `[wat jij anders zou aanpakken]`.

- **TODO:** de `[...]`-regels invullen met een eigen moment.

### 11. Slot — *samen*
> "Bedankt. Vragen?"

Repo-link bij de hand voor een vraag over de code of het data contract: `github.com/noaRoblesLevy/QN-SENTRY`.
