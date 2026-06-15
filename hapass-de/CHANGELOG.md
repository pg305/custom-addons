# Changelog

## [0.4.7] – 2026-06-15

### Neu: Login-Seite Verbesserungen
- Logo und App-Name auf der Login-Seite sind klickbare Links zu `sv-langschede.de`
- Neuer prominenter Button "Zurück zur Webseite" unterhalb des Login-Formulars

---

## [0.4.6] – 2026-06-15

### Neu: Mitglieder-Aktivität in der History
- Aktionen von Mitgliedern (Geräte schalten etc.) werden jetzt im Activity-Tab des Admin-Dashboards angezeigt
- Mitglieder-Befehle lösen außerdem einen HA-Logbuch-Eintrag und ein `ha_pass_activity`-Event aus
- Neue DB-Migration (006): Spalte `member_label` in `access_log`-Tabelle ergänzt
- `list_access_logs` nutzt `COALESCE(token_label, member_label)` — zeigt sowohl Gast- als auch Mitglieder-Einträge

---

## [0.4.5] – 2026-06-15

### Verbesserungen
- **Kein Ablaufdatum**: Zeile im Admin-Dashboard und Countdown-Leiste im Gast-PWA werden komplett ausgeblendet, wenn kein Ablaufdatum gesetzt ist
- **Desktop-Layout**: Geräte-Karten werden auf größeren Bildschirmen in zwei Spalten nebeneinander angezeigt (auf Mobilgeräten weiterhin einspaltig)
- **Zurück-Navigation gesperrt**: Nach Ablauf einer Sitzung verhindert `history.pushState` das Zurücknavigieren zur aktiven Ansicht (betrifft PWA-Overlay und statische Ablauf-Seite)
- **Wochentag-Fehlermeldung**: Zugriff an einem nicht erlaubten Wochentag zeigt eigene Meldung "Heute kein Zugang" mit passendem Icon statt generischer Ablaufmeldung
- **Logo-Link**: Logo und Vereinsname im Gast-PWA-Header sind klickbare Links zu `sv-langschede.de`
- **Webseite-Button**: Direktlink zur Vereinswebseite im Header ergänzt
- **Profilicon entfernt**: Kreisförmiges Personen-Icon neben dem Token-Namen wurde entfernt

---

## [0.4.4] – 2026-06-15

### Änderungen
- Interne Versionsnummer angepasst

---

## [0.4.3] – 2026-06-15

### Neu: Optionaler Passwortdialog bei Erstanmeldung

- Neues Mitglieder werden nach dem ersten Login nicht mehr auf eine separate Seite weitergeleitet
- Stattdessen erscheint ein Dialog-Overlay auf der Geräteansicht: **"Eigenes Passwort setzen?"**
  - "Passwort setzen": Mindestens 6 Zeichen, ein Groß- und ein Kleinbuchstabe erforderlich
  - "Beim gegebenen Passwort bleiben": Bestehendes Passwort wird behalten, Flag wird gelöscht
- Beide Optionen löschen das `must_change_password`-Flag, sodass der Dialog nie wieder erscheint
- Passwort-Validierung auf dem Server erweitert: Groß- und Kleinbuchstaben werden jetzt explizit geprüft
- Neue API-Endpunkte: `POST /me/skip-password-change`
- Neue DB-Funktion: `clear_must_change_password`

---

## [0.4.2] – 2026-06-14

### Bugfix
- Mitglieder-PWA zeigte sofort "Abgelaufen" und lud keine Geräte — `expires_at` war auf 0 gesetzt, JS-Ablaufcheck löste fälschlicherweise aus

---

## [0.4.1] – 2026-06-14

### Bugfix
- HA-Ingress: `/` leitet wieder direkt zum Admin-Dashboard weiter (kein Login nötig wenn über HA Seitenleiste geöffnet)

---

## [0.4.0] – 2026-06-14

### Neu: Mitgliederzugang & Templates

**User Management**
- Vereinsmitglieder können sich nun unter `/` mit Benutzername und Passwort anmelden
- Jedes Mitglied bekommt eine eigene Gerätekachel-Ansicht (dieselbe PWA wie Gast-Links), mit dem Benutzernamen als Titel
- Logout-Button in der Mitglieder-Ansicht
- Member-Sessions bleiben 30 Tage gültig
- Rate-Limiting beim Login: 5 Versuche/Minute pro IP

**Templates**
- Templates definieren Gerätelisten + erlaubte Wochentage (z. B. Template "Trainer" = Halle Mo–Sa)
- Templates können im Admin-Panel erstellt, bearbeitet und gelöscht werden
- Mitglieder werden einem Template zugewiesen; das Template bestimmt, was sie steuern dürfen
- Wenn ein Template bearbeitet wird, greifen die Änderungen für alle zugewiesenen Mitglieder sofort

**Admin-Panel**
- Drei neue Reiter: **Gast-Token** (wie bisher), **Mitglieder**, **Templates**
- Mitglieder anlegen, bearbeiten (Passwort ändern, Template wechseln, aktivieren/deaktivieren), löschen
- Templates anlegen, bearbeiten, löschen

**Slug-Links**
- Das bestehende `/g/{slug}` System bleibt vollständig unverändert

### Technisch
- Neue Alembic-Migration `004_members_templates` (automatisch beim Start)
- Neue Tabellen: `templates`, `members`, `member_sessions`
- Neuer Router `app/routers/member.py`
- `guest_pwa.html` jetzt parametergesteuert (`api_base`, `is_member`)

---

## [0.3.5] und früher

Siehe Git-History.
