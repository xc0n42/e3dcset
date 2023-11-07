# e3dcset

Dieses Kommandozeilen Tool basiert auf dem [Code von mschlappa](https://github.com/mschlappa/e3dcset.git)

E3/DC beschränkt die Funktion des manuellen Ladens auf eine einmalige Ausführung am Tag. Ein nächtliches Laden aus dem Netz bei leerem Akku war mit dem RSCP Tag START_MANUAL_CHARGE nicht möglich. 

Mit dem RSCP Tag REQ_SET_POWER_MODE lässt sich die E3DC für einige Sekunden in einen spezifischen Power-Mode schalten, daher läuft dieses Tool für die mit dem Parameter `-t` angegebene Zeit in Minuten. Dabei wird der Request alle 5 Sekunden an die E3/DC geschickt. Wird das Programm beendet, schaltet die E3/DC automatisch zurück in den Normalmodus.

Neben der oben genannten Code-Basis enthält das Programm Teile auf dem von E3DC zur Verfügung gestellten Beispielprogramm sowie 
einige Codestellen aus dem Tool [E3DC-Control] von Eberhard Mayer.


# Installation

Zunächst das git Repository klonen mit:

```sh
$ git clone https://github.com/xc0n42/e3dcset.git
```
In das soeben angelegte Verzeichnis ``e3dcset`` wechseln und die Konfigurationsdatei Datei ``e3dcset.config`` mit einem Editor Deiner Wahl öffnen (z.B. nano)

```sh
$ cd e3dcset
$ nano e3dcset.config
```

- IP-Adresse sowie Port (Standardport=5033) auf die des eigenen Hauskraftwerkes anpassen.
- Username / Kennwort vom E3DC Online Account sowie das im Gerät zuvor selbst festgelegte RSCP-Kennwort eintragen 
- ggf. debug auf 1 setzen, falls zusaetzliche Ausgaben (z.B zur Fehlersuche) gewuenscht werden
- Datei beim Verlassen speichern ;-)

```sh
server_ip = 192.168.xxx.yyy
server_port = 5033
e3dc_user = xxx@xxxxx.xx
e3dc_password = xxxxx
aes_password = xxxxx
```
Die Min/Max Werte sind bereits auf sinnvolle Werte eingestellt und müssen i.d.R. nicht angepasst werden (Ausnahme: z.B. S10 Pro wg. erhöhter Lade-/Entladeleistung)


Kompilieren des Tools mit:

```sh
$ make
```
Hinweis: Das kann auf einem älteren Raspberry Pi ein paar Minuten dauern ...

# Aufrufbeispiele

Nachdem das Kompilieren angeschlossen ist, kann man das Tool ohne Parameter aufrufen.

Es wird dann eine kleine Hilfe ausgegeben.

Bedeutung der Kürzel:
-(m)ode
-(t)imeout
-power (v)alue
-power(s)ave

```sh
$ ./e3dcset

Usage: e3dcset [-m mode: 0=auto,1=idle,2=discharge,3=charge,4=grid charge] [-v charge/discharge value] [-t runtime in minutes] [-s 0=powersave off,1=powersave on] [-p Pfad zur Konfigurationsdatei]
```

Power Save Mode einschalten:

```sh
$ ./e3dcset -s 1
```

Idle Mode für 5 Minuten
Schaltet die Speicherladung ab und speist bei PV Leistung komplett ins Netz ein

```sh
$ ./e3dcset -m 1 -v 1000 -t 5 -p /home/pi/meine.config
```

Charge Mode für 30 Minuten
Lädt mit max. 800W, Überschuss geht ins Netz. Steht nicht genug PV Leistung zur Verfügung, wird zusätzlich aus dem Netz geladen

```sh
$ ./e3dcset -m 3 -v 800 -t 30 -p /home/pi/meine.config
```

Grid charge mode für eine Stunde 
Lädt mit max. 800W, Überschuss geht ins Netz. Steht nicht genug PV Leistung zur Verfügung, wird zusätzlich aus dem Netz geladen
(Unterschied zu Mode 3 ist noch unklar)

```sh
$ ./e3dcset -m 4 -v 1000 -t 60 -p /home/pi/meine.config
```
 
