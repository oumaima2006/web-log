
import re
import csv
import json
from datetime import datetime
from datetime import datetime, timedelta
from collections import defaultdict, deque
# Lire la configuration

with open("config.json", "r", encoding="utf-8") as file:
    config = json.load(file)

WINDOW_MINUTES = config["window_minutes"]
THRESHOLD = config["auth_threshold"]

MIN_REQUESTS = config["min_requests"]
THRESHOLD_404 = config["threshold_404"]

# Fonction pour analyser une ligne HTTP
def parse_log_line(line):

    pattern = (
        r'(\S+) \S+ \S+ '
        r'\[([^\]]+)\] '
        r'"(\S+) (\S+) (\S+)" '
        r'(\d{3}) (\S+)'
    )

    match = re.match(pattern, line)

    if match is None:
        return None

    ip = match.group(1)
    date = match.group(2)
    method = match.group(3)
    url = match.group(4)
    protocol = match.group(5)
    status = int(match.group(6))
    size = match.group(7)

    return {
        "ip": ip,
        "date": date,
        "method": method,
        "url": url,
        "protocol": protocol,
        "status": status,
        "size": size
    }


# Lire le fichier access.log
with open("access.log", "r", encoding="utf-8") as file:

    for line in file:

        result = parse_log_line(line)

        if result is not None:

            print("-------------------------")
            print("IP:", result["ip"])
            print("Date:", result["date"])
            print("Method:", result["method"])
            print("URL:", result["url"])
            print("Protocol:", result["protocol"])
            print("Status:", result["status"])
            print("Size:", result["size"])

        else:
            print("Invalid log line")







# ==================================
# STATISTIQUES HTTP
# ==================================

ip_counts = {}
status_counts = {}

with open("access.log", "r", encoding="utf-8") as file:

    for line in file:

        result = parse_log_line(line)

        if result is not None:

            ip = result["ip"]
            status = result["status"]

            # Compter les requêtes par IP
            ip_counts[ip] = ip_counts.get(ip, 0) + 1

            # Compter les codes HTTP
            status_counts[status] = status_counts.get(status, 0) + 1

print("\n========== STATISTIQUES ==========")

print("\nNombre de requêtes par IP:")

for ip, count in ip_counts.items():
    print(ip, ":", count)


print("\nNombre de réponses par code HTTP:")

for status, count in status_counts.items():
    print(status, ":", count)



# ==================================
# DETECTION 401 ET 403 AVEC FENETRE DE TEMPS
# ==================================



auth_events = []

# Lire les logs et récupérer les erreurs 401 et 403
with open("access.log", "r", encoding="utf-8") as file:

    for line in file:

        result = parse_log_line(line)

        if result is not None:

            status = result["status"]

            if status in (401, 403):

                try:
                    timestamp = datetime.strptime(
                        result["date"],
                        "%d/%b/%Y:%H:%M:%S %z"
                    )

                    auth_events.append({
                        "ip": result["ip"],
                        "date": timestamp,
                        "url": result["url"],
                        "status": status
                    })

                except ValueError:
                    print("Date invalide:", result["date"])


# Trier les événements par date
auth_events.sort(key=lambda event: event["date"])

# Détection des rafales
windows = defaultdict(deque)
alerts = []

window_duration = timedelta(minutes=WINDOW_MINUTES)

for event in auth_events:

    ip = event["ip"]
    current_time = event["date"]

    # Récupérer les événements de cette IP
    current_window = windows[ip]

    # Supprimer les événements trop anciens
    while current_window and (
        current_time - current_window[0]["date"] > window_duration
    ):
        current_window.popleft()

    # Ajouter le nouvel événement
    current_window.append(event)

    # Vérifier le seuil
    if len(current_window) == THRESHOLD:

        alerts.append({
            "ip": ip,
            "count": len(current_window),
            "start": current_window[0]["date"],
            "end": current_time,
            "type": "AUTH_BURST"
        })


# Afficher les alertes
print("\n========== AUTHENTICATION ALERTS ==========")

for alert in alerts:

    print("ALERT:", alert["type"])
    print("IP:", alert["ip"])
    print("Failed requests:", alert["count"])
    print("Start:", alert["start"])
    print("End:", alert["end"])
    print("--------------------------------")


# ==================================
# DETECTION D'UNE FORTE PROPORTION DE 404
# ==================================

total_requests = {}
not_found_counts = {}

with open("access.log", "r", encoding="utf-8") as file:

    for line in file:

        result = parse_log_line(line)

        if result is not None:

            ip = result["ip"]
            status = result["status"]

            total_requests[ip] = total_requests.get(ip, 0) + 1

            if status == 404:
                not_found_counts[ip] = not_found_counts.get(ip, 0) + 1


print("\n========== 404 ENUMERATION ALERTS ==========")


for ip, total in total_requests.items():

    errors_404 = not_found_counts.get(ip, 0)

    proportion = errors_404 / total

    if total >= MIN_REQUESTS and proportion >= THRESHOLD_404:

        print("ALERT: POSSIBLE_ENUMERATION")
        print("IP:", ip)
        print("Total requests:", total)
        print("404 errors:", errors_404)
        print("404 proportion:", round(proportion * 100, 2), "%")
        print("--------------------------------")


# ==================================
# CHRONOLOGIE DES EVENEMENTS
# ==================================

events = []

with open("access.log", "r", encoding="utf-8") as file:

    for line in file:

        result = parse_log_line(line)

        if result is not None:

            try:
                date = datetime.strptime(
                    result["date"],
                    "%d/%b/%Y:%H:%M:%S %z"
                )

                events.append({
                    "date": date,
                    "ip": result["ip"],
                    "url": result["url"],
                    "status": result["status"]
                })

            except ValueError:
                continue


# Trier les événements par date
events.sort(key=lambda event: event["date"])


# Afficher la chronologie
print("\n========== TIMELINE ==========")

for event in events:

    print(
        event["date"],
        "| IP:", event["ip"],
        "| URL:", event["url"],
        "| STATUS:", event["status"]
    )




# ==================================
# EXPORTER LA CHRONOLOGIE EN CSV
# ==================================

with open("timeline.csv", "w", newline="", encoding="utf-8") as file:

    writer = csv.writer(file, delimiter=";")

    # Ecrire les titres des colonnes
    writer.writerow(["Date", "IP", "URL", "Status"])

    # Ecrire les evenements
    for event in events:

        writer.writerow([
            event["date"].strftime("%d/%m/%Y %H:%M:%S"),
            event["ip"],
            event["url"],
            event["status"]
        ])

print("\nExportation terminee !")
print("Fichier cree : timeline.csv")

