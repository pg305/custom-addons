# Changelog

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
