# Belegbox – Test-App 0.5.3.0

Abos, Verträge, Geräte und Belege an einem Ort. Alle Daten werden mit deinem Passwort verschlüsselt und bleiben auf dem Handy. Es gibt keinen Server und keine Verbindung zu fremden Diensten.

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
| `icons/` | App-Icons, `badge-96.png` für spätere Push-Nachrichten |

## Online stellen

1. Ordnerinhalt auf einen beliebigen statischen Hoster mit HTTPS hochladen (ohne HTTPS funktionieren Verschlüsselung und Service Worker nicht).
2. Am besten in einen eigenen Unterordner oder auf eine eigene Subdomain, nicht in denselben Ordner wie eine andere App.
3. Auf dem Android-Handy in Chrome öffnen → Menü → „App installieren“ bzw. „Zum Startbildschirm“.

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

## Sicherung

Der verschlüsselte Tresor liegt doppelt im Browser (localStorage und IndexedDB). Fehlt eine Kopie oder ist sie beschädigt, stellt die App sie beim Start aus der anderen wieder her. Gegen Browserwechsel, Deinstallieren der App oder gelöschte Websitedaten hilft nur die Sicherungsdatei. Die App erinnert nach 14 Tagen oder 5 Änderungen.

Daten → „Sicherung erstellen“. Die Datei (`.belegbox`) ist mit dem Passwort verschlüsselt, das beim Sichern galt, und enthält auch alle PDFs und Dokumente. Über das Teilen-Menü direkt in die Cloud legen. Die App erinnert, wenn die letzte Sicherung älter als 30 Tage ist.

Wiederherstellen: auf dem neuen Handy beim Einrichten „Sicherung wiederherstellen“ wählen, oder später unter Daten → „Sicherung laden“.

## Kalender

Daten → „Fristen in Kalender exportieren“ erzeugt eine `.ics`-Datei mit Erinnerungen 7 Tage und 1 Tag vorher. Standardmäßig mit neutralen Titeln, damit keine Anbieter in einem synchronisierten Kalender landen. Nach Änderungen erneut exportieren; Termine mit gleicher Kennung werden aktualisiert.

## Testen

- Passwort anlegen, Beispieldaten anschauen, eigene Einträge anlegen
- Sperren, falsches und richtiges Passwort probieren
- Sicherung erstellen, App-Daten im Browser löschen, Sicherung wiederherstellen
- Kalenderexport öffnen und prüfen, ob die Erinnerungen ankommen
