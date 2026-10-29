# MyBelegBox – Test-App 0.9.5.0

Abos, Verträge, Geräte und Belege an einem Ort. Alle Daten werden mit deinem Passwort verschlüsselt und bleiben auf dem Handy. Es gibt keinen Server. Einzige mögliche Verbindung: die optionale automatische Sicherung in dein eigenes privates GitHub-Repo (nur verschlüsselte Daten).

## Neu in 0.9.5

- Suche, Formulare und Rückfragen sehen jetzt in allen drei Boxen gleich aus: Suche als Blatt von unten, Formular-Knöpfe „Abbrechen“ und „Speichern“ rechts, Löschen und neue Version mit Rückfrage statt zweimal tippen bzw. nur Hinweis.

## Neu in 0.9.4

- Erinnerung an die Datensicherung als Karte oben in der Übersicht (wie in MySmartBox und MyGesundBox) statt Banner auf allen Seiten. Antippen öffnet „Datensicherung“.
- Kopfzeile und Neu-Knopf in gleicher Größe wie in den anderen Boxen; der App-Name passt auch auf schmale Handys.

## Neu in 0.9.3

- **Gleiche Optik wie MySmartBox und MyGesundBox** bei „Daten & Sicherheit“: Bereiche Sicherheit, Datensicherung und App-Update mit Zwischenüberschriften, gleichen Beschriftungen und Knöpfen.
- „GitHub einrichten“, „App-Update verbinden“ und „Passwort ändern“ öffnen jetzt ein kleines Fenster statt Eingabefelder im Bereich.
- Sperrbildschirm als Karte wie in den anderen Boxen, Hinweis „Neue Version“ und Meldungen unten im gleichen Stil.

## Neu in 0.9.2

- **Verbindung zur MySmartBox**: Im Gerät der MySmartBox „In der MyBelegBox“ antippen. Gibt es das Gerät hier schon (z. B. „TV“ ↔ „Fernseher Wohnzimmer“), schlägt die MyBelegBox es zum Verknüpfen vor, sonst wird es neu angelegt. Übertragen werden nur Name und Raum, gespeichert nur die Verknüpfung (`ext`). Im Gerät führt „In der MySmartBox öffnen“ zurück.
- Links aus den anderen Boxen kommen über den Teil hinter `#` an, der nicht an den Server geschickt wird (`?neu=…` funktioniert weiterhin).

## Neu in 0.9.1

- **Verbindung zur MyGesundBox**: Brillen (als Gerät) und Kontaktlinsen-Abos (als Vertrag) lassen sich aus der MyGesundBox übernehmen. Die MyGesundBox öffnet dafür die MyBelegBox mit einem vorausgefüllten Formular (`?neu=…`), gespeichert wird nur eine Verknüpfung (`ext`). Im Eintrag führt „In der MyGesundBox öffnen“ zurück, `?ref=…` öffnet einen übernommenen Eintrag. Sehstärke-Werte werden nicht übertragen.
- Neue Kategorie **Gesundheit** bei Geräten und Verträgen, Zahlweise **halbjährlich**.

## Neu in 0.7

- **Teilen aus anderen Apps**: PDF oder Bild in Gmail, Amazon usw. → Teilen → MyBelegBox. Nach dem Entsperren wählst du, zu welchem Gerät oder Vertrag die Datei gehört, oder legst einen neuen Eintrag an. Bis dahin liegt die Datei kurz unverschlüsselt im Eingangsfach der App.
- **Erinnerungen** (Daten → Erinnerungen): Benachrichtigung, wenn in den nächsten 14 Tagen eine Frist abläuft, auf Android mit Punkt am App-Icon. Android prüft auch bei geschlossener App, meist etwa einmal am Tag. Dafür liegen nur die Termine ohne Namen und Beträge unverschlüsselt auf dem Handy. Eine Zahl am Icon gibt es für Web-Apps auf Android nicht.
- **Weiterlaufen lassen**: Im Vertrag „Weiterlaufen lassen“ – für die aktuelle Laufzeit keine Erinnerung, ab der nächsten wieder.
- **Schnellaktionen**: Lange auf das App-Icon drücken → Beleg fotografieren, Neues Gerät, Neues Abo, Suchen.
- **Kündigung schreiben**: fertiger Text mit Kunden- und Vertragsnummer zum Kopieren oder Teilen. Der Absender wird verschlüsselt gespeichert.
- **Mangel melden**: Reklamationstext mit allen Gerätedaten, auf Wunsch zusammen mit den Belegen teilen.
- **Seriennummer scannen**: Barcode oder QR-Code am Typenschild mit der Kamera lesen.
- **Suche** (Lupe oben): über Namen, Seriennummern, Notizen, Kundennummern und Dateinamen.
- **Kosten pro Tag** in Übersicht, Vertragsliste und Details.
- **Abo-Check**: Alle 3 Monate fragt die App bei Streaming, Software, Fitness und Sonstigem nach, ob du es noch nutzt.
- **Jahresrückblick**: Daten → Jahresrückblick, vom 1. Dezember bis 15. Januar auch als Hinweis in der Übersicht.

## Gesten & Bewegung (ab 0.4)

- Links/rechts wischen wechselt zwischen Übersicht, Geräte und Verträge.
- Detail- und Formularfenster lassen sich am Griff oder von oben nach unten wegziehen.
- Oben auf der Seite nach unten ziehen: Fristen neu berechnen und nach Updates suchen.
- „Neu“ öffnet einen Fächer: Gerät, Abo / Vertrag oder direkt „Beleg fotografieren“.
- Tresor-Animation beim Entsperren und Sperren, Garantie-Ringe um die Geräte, hochzählende Beträge, Haken-Animation beim Speichern und Kündigen, leichtes Kippen mit Glanz über den Lagesensor, kurzes Vibrieren bei Aktionen.
- Wer in Android „Animationen entfernen“ eingeschaltet hat, bekommt die ruhige Version ohne Effekte.

## Dateien

| Datei | Zweck |
|---|---|
| `index.html` | Seite und Gestaltung |
| `app.js` | gesamte App-Logik inkl. Verschlüsselung |
| `sw.js` | Service Worker (offline nutzbar, Update-Hinweis) |
| `manifest.webmanifest` | Name, Farben, Icons für „Zum Startbildschirm“ |
| `vendor/pdfjs/` | pdf.js von Mozilla (Apache-2.0) zum Anzeigen von PDFs, unverändert, wird nur bei Bedarf geladen |
| `icons/` | App-Icons, `belegbox-badge-96.png` für spätere Push-Nachrichten |

## Online stellen

1. Ordnerinhalt auf einen beliebigen statischen Hoster mit HTTPS hochladen (ohne HTTPS funktionieren Verschlüsselung und Service Worker nicht).
2. Am besten in einen eigenen Unterordner oder auf eine eigene Subdomain, nicht in denselben Ordner wie eine andere App.
3. Auf dem Android-Handy in Chrome öffnen → Menü → „App installieren“ bzw. „Zum Startbildschirm“.

## App-Update aus der App (ab 0.9)

Daten → **App-Update**: einmal das App-Repo (`jazm-belegbox/jazm-belegbox.github.io`) und einen eigenen Fine-grained-Zugangsschlüssel eintragen – nur für dieses Repo, Rechte **Contents: Read and write** und **Actions: Read**. Danach „Update-Zip hochladen“ und das Paket wählen. Der Ablauf `.github/workflows/paket.yml` entpackt die Zip, prüft, dass `APP_VERSION` (app.js) und Cache-Nummer (sw.js) übereinstimmen und die Version nicht älter ist, übernimmt die Dateien, löscht die Zip und veröffentlicht. Die App zeigt den Fortschritt und meldet, sobald die neue Version online ist.

Ohne App geht es auch: Zip auf GitHub über „Add file → Upload files“ ins Hauptverzeichnis laden.

Ein Paket enthält nur die geänderten Dateien; was nicht in der Zip ist (z. B. `vendor/`), bleibt unverändert.

## Neue Version veröffentlichen

1. In `sw.js` die Nummer in `CACHE = 'belegbox-…'` erhöhen.
2. In `app.js` `APP_VERSION` auf dieselbe Nummer setzen.
3. Hochladen. Die App zeigt oben „Neue Version verfügbar“ mit Knopf „Aktualisieren“.

## Sicherheit

- AES-256-GCM, Schlüssel per PBKDF2 (SHA-256, 600.000 Runden) aus dem Passwort. Gespeichert werden nur Salt, IV und verschlüsselte Daten.
- Automatische Sperre nach 5 Minuten ohne Eingabe oder 1 Minute im Hintergrund.
- Belege & Dokumente (PDF/Bild) liegen einzeln in IndexedDB, jeweils mit demselben Datenschlüssel AES-256-GCM-verschlüsselt. Angezeigt werden sie nur im Arbeitsspeicher, nichts landet unverschlüsselt im Download-Ordner (außer über „Teilen“).
- IBANs und Kartennummern werden beim Speichern abgelehnt.
- Content-Security-Policy erlaubt nur Dateien von der eigenen Adresse, keine externen Skripte, Schriften oder Verbindungen.
- **Kein Passwort-Reset möglich.** Passwort vergessen = Daten weg (außer du hast es im Passwortmanager).

## Automatische Sicherung (GitHub)

Daten → „Automatische Sicherung (GitHub)“: Konto, privates Repo und einen Fine-grained-Zugangsschlüssel (nur dieses Repo, „Contents: Read and write“) eintragen. Danach landen nach jeder Änderung `vault.json` (der verschlüsselte Tresor) und `files/<id>.bin` (verschlüsselte Dokumente) im Repo. Jede Sicherung ist ein Commit, ältere Stände bleiben in der Versionsgeschichte. Öffentliche Repos werden abgelehnt, ein fremder Tresor im Repo wird nie automatisch überschrieben, und im Repo wird nichts gelöscht.

Wiederherstellen: auf „Tresor einrichten“ → „Aus GitHub wiederherstellen“, Zugangsschlüssel eingeben, dann mit dem Passwort entsperren.

## Sicherung

Der verschlüsselte Tresor liegt doppelt im Browser (localStorage und IndexedDB). Fehlt eine Kopie oder ist sie beschädigt, stellt die App sie beim Start aus der anderen wieder her. Gegen Browserwechsel, Deinstallieren der App oder gelöschte Websitedaten hilft nur die Sicherungsdatei. Die App erinnert nach 14 Tagen oder 5 Änderungen.

Daten → „Sicherung erstellen“. Die Datei (`.belegbox`) ist mit dem Passwort verschlüsselt, das beim Sichern galt, und enthält auch alle PDFs und Dokumente. Über das Teilen-Menü direkt in die Cloud legen. Die App erinnert, wenn die letzte Sicherung älter als 30 Tage ist.

Wiederherstellen: auf dem neuen Handy beim Einrichten „Sicherung wiederherstellen“ wählen, oder später unter Daten → „Sicherung laden“.

## Kalender

Daten → „Fristen in Kalender exportieren“ erzeugt eine `.ics`-Datei mit Erinnerungen 7 Tage und 1 Tag vorher. Standardmäßig mit neutralen Titeln, damit keine Anbieter in einem synchronisierten Kalender landen. Nach Änderungen erneut exportieren; Termine mit gleicher Kennung werden aktualisiert.

## Testen

- Passwort anlegen, eigene Einträge anlegen
- Sperren, falsches und richtiges Passwort probieren
- Sicherung erstellen, App-Daten im Browser löschen, Sicherung wiederherstellen
- Kalenderexport öffnen und prüfen, ob die Erinnerungen ankommen
