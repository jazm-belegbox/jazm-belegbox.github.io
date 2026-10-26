# Belegbox – Test-App 0.1.0.1

Abos, Verträge, Geräte und Belege an einem Ort. Alle Daten werden mit deinem Passwort verschlüsselt und bleiben auf dem Handy. Es gibt keinen Server und keine Verbindung zu fremden Diensten.

## Dateien

| Datei | Zweck |
|---|---|
| `index.html` | Seite und Gestaltung |
| `app.js` | gesamte App-Logik inkl. Verschlüsselung |
| `sw.js` | Service Worker (offline nutzbar, Update-Hinweis) |
| `manifest.webmanifest` | Name, Farben, Icons für „Zum Startbildschirm“ |
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
- IBANs und Kartennummern werden beim Speichern abgelehnt.
- Content-Security-Policy erlaubt nur Dateien von der eigenen Adresse, keine externen Skripte, Schriften oder Verbindungen.
- **Kein Passwort-Reset möglich.** Passwort vergessen = Daten weg (außer du hast es im Passwortmanager).

## Sicherung

Daten → „Sicherung erstellen“. Die Datei (`.belegbox`) ist mit dem Passwort verschlüsselt, das beim Sichern galt. Über das Teilen-Menü direkt in die Cloud legen. Die App erinnert, wenn die letzte Sicherung älter als 30 Tage ist.

Wiederherstellen: auf dem neuen Handy beim Einrichten „Sicherung wiederherstellen“ wählen, oder später unter Daten → „Sicherung laden“.

## Kalender

Daten → „Fristen in Kalender exportieren“ erzeugt eine `.ics`-Datei mit Erinnerungen 7 Tage und 1 Tag vorher. Standardmäßig mit neutralen Titeln, damit keine Anbieter in einem synchronisierten Kalender landen. Nach Änderungen erneut exportieren; Termine mit gleicher Kennung werden aktualisiert.

## Testen

- Passwort anlegen, Beispieldaten anschauen, eigene Einträge anlegen
- Sperren, falsches und richtiges Passwort probieren
- Sicherung erstellen, App-Daten im Browser löschen, Sicherung wiederherstellen
- Kalenderexport öffnen und prüfen, ob die Erinnerungen ankommen
