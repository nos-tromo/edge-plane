<!--
VORLAGE: Datenschutzhinweise für die Nutzenden (docs/configuration.md#portal-information-pages)

So wird sie verwendet:
1. Nach info/privacy.md kopieren; diese Datei selbst wird nie ausgeliefert.
2. Alle [Platzhalter] ersetzen.
3. Jede mit "(prüfen)" markierte Angabe gegen die .env-Dateien dieses Hosts
   abgleichen. Genannt sind die Voreinstellungen des Releases und die
   Variable, mit der ein Host sie ändert.
4. Den Text von der/dem Datenschutzbeauftragten freigeben lassen. Die
   Rechtsgrundlagen sind bewusst Platzhalter: Die rechtliche Einordnung trifft
   der Verantwortliche, nicht dieses Repository (deploy, ADR 0003).
5. Danach EDGE_PRIVACY_POLICY_LINK=true setzen und `make up`; die
   Anmeldeseite verlinkt diese Seite dann.

Die Seite ist ohne Anmeldung erreichbar. Sie darf nichts enthalten, was nur
Angemeldete sehen sollen. HTML-Kommentare wie dieser erscheinen nicht auf der
Seite.
-->
# Datenschutzhinweise

Stand: [Datum]

Diese Hinweise informieren Sie als Nutzerin oder Nutzer darüber, welche
personenbezogenen Daten über Sie verarbeitet werden, wenn Sie dieses Portal
und die darüber erreichbaren Anwendungen nutzen.

## Verantwortlich

[Name der Behörde]\
[Anschrift]\
[Kontakt, z. B. Funktionspostfach]

## Datenschutzbeauftragte oder Datenschutzbeauftragter

[Name oder Funktion]\
[Kontakt]

## Welche Daten verarbeitet werden, wozu und wie lange

<!--
"Bis zur Löschung des Kontos": Wird ein Konto aus authelia/users.yml
entfernt, löscht Authelia seine TOTP-Konfiguration und Einstellungen nicht
selbst (docs/decisions/0003-auth-retention-deletes-authelia-records.md).
Die Angabe stimmt nur, wenn sie beim Entfernen des Kontos mitgelöscht werden.
-->

| Daten | Zweck | Speicherdauer |
|---|---|---|
| Ihr Konto: Benutzername, Anzeigename, dienstliche E-Mail-Adresse, Gruppenzugehörigkeit, Passwort (nur als Hash), zweiter Faktor | Anmeldung und Berechtigungen | bis zur Löschung des Kontos |
| Anmeldeversuche: Zeitpunkt, Konto, Erfolg oder Fehlschlag, Netzwerkadresse Ihres Geräts | Schutz vor unbefugtem Zugriff, Datenschutzkontrolle | 30 Tage im Anmeldedienst (`EDGE_AUTH_RETENTION_DAYS`, prüfen); im Datenschutz-Protokoll 1 Jahr (`AUDIT_RETENTION` in obs-plane, prüfen) |
| Anmeldesicherheit: Einmalcodes für die Passwortänderung, Zeitpunkte verwendeter Codes des zweiten Faktors, vorübergehende Sperren nach Fehlversuchen (Konto oder Netzwerkadresse) | Schutz vor unbefugtem Zugriff | 30 Tage nach Ablauf bzw. Aufhebung (`EDGE_AUTH_RETENTION_DAYS`, prüfen); dauerhafte Sperren bis zu ihrer Aufhebung |
| Sitzung: das Cookie `authelia_session` | angemeldet bleiben | 12 Stunden, nach 4 Stunden ohne Aktivität beendet; mit „Angemeldet bleiben“ 2 Monate (`EDGE_SESSION_*`, prüfen) |
| Zugriffsprotokoll: Zeitpunkt, Konto, aufgerufene Adresse ohne Suchparameter, Ergebnis, Netzwerkadresse, Anfragekennung | Datenschutzkontrolle, Sicherheit | 1 Jahr (`AUDIT_RETENTION` in obs-plane, prüfen) |
| Protokoll der Verarbeitungen in den Anwendungen: wer wann welche Daten erfasst, abgefragt, übermittelt oder gelöscht hat, mit dem angegebenen Zweck oder Aktenzeichen. Inhalte werden nicht protokolliert. | Datenschutzkontrolle | 1 Jahr (`AUDIT_RETENTION` in obs-plane, prüfen) |
| Betriebsprotokolle: Fehler- und Leistungsdaten, um personenbezogene Daten bereinigt | Betrieb und Fehlerbehebung | 30 Tage (`LOKI_RETENTION` in obs-plane, prüfen) |
| Design-Einstellung (hell oder dunkel) | Anzeige | nur in Ihrem Browser gespeichert, bis Sie sie zurücksetzen |

Was Sie in den Anwendungen selbst verarbeiten:

- **docint:** Dokumente werden 365 Tage nach dem Hinzufügen gelöscht
  (`DOCUMENT_RETENTION_DAYS`, prüfen), Chats und Berichte zusammen mit ihrer
  ältesten Quelle. Chats können Sie jederzeit selbst löschen.
- **Nextext:** Ihre Aufnahme bleibt gespeichert, bis Sie den Auftrag löschen
  oder der Dienst neu startet. Ergebnisdateien entstehen erst beim
  Herunterladen und werden nicht gespeichert.
- **translator:** speichert keine Texte.
- **Ghostwriter:** Chats werden 90 Tage nach ihrem Beginn gelöscht
  (`GHOSTWRITER_CHAT_RETENTION_DAYS`, prüfen), angehängte Dateien und
  Ergebnisse mit dem Chat, spätestens nach 7 Tagen (`WORKBENCH_RETENTION_DAYS`,
  prüfen); dazu zählen Code, Ausgaben und Tabellenvorschauen der Werkzeuge.
  Protokolliert werden Konto, Aktion und Verweise, keine Nachrichteninhalte;
  das Nachdenken des Modells wird weder angezeigt noch gespeichert.

## Rechtsgrundlage

[Rechtsgrundlagen einsetzen, getrennt nach den Verarbeitungen oben: Konto und
Anmeldung, Protokollierung, Fachanwendungen]

## Wer die Daten sieht

<!--
Zuordnung zu den Gruppen in authelia/users.yml: Betrieb = `admins`,
Datenschutzkontrolle = `audit`. Beide sind bewusst getrennt.
-->

- **Betrieb:** Die Administration sieht Betriebsprotokolle und Monitoring,
  aber nicht das Datenschutz-Protokoll.
- **Datenschutzkontrolle:** Nur [benannte Stelle oder Personen] lesen das
  Datenschutz-Protokoll. Jeder dieser Zugriffe wird selbst protokolliert.
- **Weitergabe:** [keine, oder Empfänger nennen]. Das System ist vom Internet
  getrennt. Die KI-Modelle laufen auf eigenen Servern; es werden keine Daten
  an externe Dienste übermittelt.

## Wofür die Protokolle verwendet werden

Die Protokolle dienen ausschließlich [Zwecke der Protokollierung, z. B.
Datenschutzkontrolle, Eigenüberwachung, Sicherstellung von Integrität und
Sicherheit der Daten]. [Regelung zur Leistungs- und Verhaltenskontrolle laut
Dienstvereinbarung.] Näheres regelt [Titel und Datum der Dienstvereinbarung].

## KI-Ergebnisse

Einige Anwendungen erzeugen Ergebnisse mit KI. Diese Ergebnisse sind
Arbeitshilfen; Entscheidungen treffen Menschen. Mehr dazu in den
[KI-Hinweisen](/info/ai).

## Ihre Rechte

Sie haben das Recht auf Auskunft, Berichtigung, Löschung und Einschränkung der
Verarbeitung sowie [Widerspruchsrecht, soweit anwendbar]. Wenden Sie sich
dafür an die oder den Datenschutzbeauftragten.

Sie können sich außerdem bei der Aufsichtsbehörde beschweren:
[Name und Anschrift der Aufsichtsbehörde].
