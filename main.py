import json
import threading
from dataclasses import dataclass,asdict
from datetime import datetime
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler,HTTPServer
from typing import Any,Dict,List,Optional


@dataclass
class Rule:
    id: int
    src_ip: Optional[str] = None
    dest_ip: Optional[str] = None
    src_port: Optional[int] = None
    dest_port: Optional[int] = None
    protocol: Optional[str] = None
    action: str = "DENY"
    enabled: bool = True

    def matches(self,packet: Dict[str,Any]) -> bool:

        if not self.enabled:
            return False

        if self.src_ip is not None and self.src_ip != packet.get("src_ip"):
            return False
        if self.dest_ip is not None and self.dest_ip != packet.get("dest_ip"):
            return False
        if self.src_port is not None and self.src_port != packet.get("src_port"):
            return False
        if self.dest_port is not None and self.dest_port != packet.get("dest_port"):
            return False
        if self.protocol is not None and self.protocol.upper() != str(packet.get("protocol","")).upper():
            return False
        return True


class Firewall:


    def __init__(self,log_file: str = "firewall.log",rules_file: str = "rules.json") -> None:
        self.rules: List[Rule] = []
        self._next_id: int = 1
        self.log_file = log_file
        self.rules_file = rules_file

        self._lock = threading.Lock()

        self._load_rules()


    def _load_rules(self) -> None:

        try:
            with open(self.rules_file,"r",encoding="utf-8") as f:
                data = json.load(f)
            for item in data:

                src_port = item.get("src_port")
                if src_port is not None:
                    src_port = int(src_port)
                dest_port = item.get("dest_port")
                if dest_port is not None:
                    dest_port = int(dest_port)
                rule = Rule(
                    id=item["id"],
                    src_ip=item.get("src_ip"),
                    dest_ip=item.get("dest_ip"),
                    src_port=src_port,
                    dest_port=dest_port,
                    protocol=item.get("protocol"),
                    action=item.get("action","DENY"),
                    enabled=bool(item.get("enabled",True)),
                )
                self.rules.append(rule)
                self._next_id = max(self._next_id,rule.id + 1)
        except FileNotFoundError:
            pass
        except Exception as e:
            print(f"[Брандмауер] Не вдалося завантажити правила: {e}")

    def _save_rules(self) -> None:

        try:
            with open(self.rules_file,"w",encoding="utf-8") as f:
                json.dump([asdict(rule) for rule in self.rules],f,indent=2)
        except Exception as e:
            print(f"[Брандмауер] Не вдалося зберегти правила: {e}")


    def add_rule(
            self,
            src_ip: Optional[str] = None,
            dest_ip: Optional[str] = None,
            src_port: Optional[int] = None,
            dest_port: Optional[int] = None,
            protocol: Optional[str] = None,
            action: str = "DENY",
            enabled: bool = True,
    ) -> Rule:

        with self._lock:
            rule = Rule(
                id=self._next_id,
                src_ip=src_ip or None,
                dest_ip=dest_ip or None,
                src_port=src_port,
                dest_port=dest_port,
                protocol=protocol.upper() if protocol else None,
                action=action.upper(),
                enabled=enabled,
            )
            self.rules.append(rule)
            self._next_id += 1
            self._save_rules()
        return rule

    def remove_rule(self,rule_id: int) -> bool:

        with self._lock:
            for idx,rule in enumerate(self.rules):
                if rule.id == rule_id:
                    del self.rules[idx]
                    self._save_rules()
                    return True
        return False

    def toggle_rule(self,rule_id: int) -> bool:

        with self._lock:
            for rule in self.rules:
                if rule.id == rule_id:
                    rule.enabled = not rule.enabled
                    self._save_rules()
                    return True
        return False

    def get_rules(self) -> List[Rule]:

        with self._lock:
            return list(self.rules)


    def detect_conflicts(self) -> Dict[str,List[tuple]]:

        duplicates: List[tuple] = []
        conflicts: List[tuple] = []
        with self._lock:
            for i,r1 in enumerate(self.rules):
                for j in range(i + 1,len(self.rules)):
                    r2 = self.rules[j]

                    if (
                            r1.src_ip == r2.src_ip
                            and r1.dest_ip == r2.dest_ip
                            and r1.src_port == r2.src_port
                            and r1.dest_port == r2.dest_port
                            and (r1.protocol or '').upper() == (r2.protocol or '').upper()
                    ):
                        if r1.action == r2.action:
                            duplicates.append((r1.id,r2.id))
                        else:
                            conflicts.append((r1.id,r2.id))
        return {"duplicates": duplicates,"conflicts": conflicts}


    def process_packet(self,packet: Dict[str,Any]) -> str:

        with self._lock:
            for rule in self.rules:
                if rule.matches(packet):
                    if rule.action == "DENY":

                        self._log_denial(packet,rule)
                    return rule.action

        return "ALLOW"


    def _log_denial(self,packet: Dict[str,Any],rule: Rule) -> None:

        entry = {
            "timestamp": datetime.utcnow().isoformat() + "Z",
            "rule_id": rule.id,
            "reason": f"Спрацювало правило заборони {rule.id}",
            "packet": {
                "src_ip": packet.get("src_ip"),
                "dest_ip": packet.get("dest_ip"),
                "src_port": packet.get("src_port"),
                "dest_port": packet.get("dest_port"),
                "protocol": packet.get("protocol"),
            },
        }
        try:
            with open(self.log_file,"a",encoding="utf-8") as f:
                f.write(json.dumps(entry) + "\n")
        except Exception as e:
            print(f"[Брандмауер] Не вдалося записати в журнал: {e}")

    def search_logs(
            self,
            src_ip: Optional[str] = None,
            dest_ip: Optional[str] = None,
            protocol: Optional[str] = None,
    ) -> List[Dict[str,Any]]:


        results: List[Dict[str,Any]] = []
        try:
            with open(self.log_file,"r",encoding="utf-8") as f:
                for line in f:
                    try:
                        entry = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    pkt = entry.get("packet",{})
                    if src_ip and pkt.get("src_ip") != src_ip:
                        continue
                    if dest_ip and pkt.get("dest_ip") != dest_ip:
                        continue
                    if protocol and pkt.get("protocol","").upper() != protocol.upper():
                        continue
                    results.append(entry)
        except FileNotFoundError:
            pass
        return results


class FirewallHTTPHandler(BaseHTTPRequestHandler):


    firewall: Firewall = None

    def _send_json(self,data: Any,status: int = HTTPStatus.OK) -> None:
        payload = json.dumps(data).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type","application/json")
        self.send_header("Content-Length",str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def do_GET(self) -> None:

        path,_,query = self.path.partition("?")
        params: Dict[str,str] = {}
        if query:
            for kv in query.split("&"):
                if "=" in kv:
                    k,v = kv.split("=",1)
                    params[k] = v
        fw = self.firewall

        if path == "/rules":
            data = [asdict(rule) for rule in fw.get_rules()]
            self._send_json(data)
        elif path == "/add":
            try:

                src_port = int(params["src_port"]) if "src_port" in params and params["src_port"] else None
                dest_port = int(params["dest_port"]) if "dest_port" in params and params["dest_port"] else None
                protocol = params.get("protocol")
                action = params.get("action","DENY")
                rule = fw.add_rule(
                    src_ip=params.get("src_ip"),
                    dest_ip=params.get("dest_ip"),
                    src_port=src_port,
                    dest_port=dest_port,
                    protocol=protocol,
                    action=action,
                )
                self._send_json(asdict(rule))
            except Exception as e:
                self._send_json({"error": str(e)},status=HTTPStatus.BAD_REQUEST)
        elif path == "/remove":
            try:
                rid = int(params.get("id","0"))
                ok = fw.remove_rule(rid)
                self._send_json({"removed": ok})
            except Exception as e:
                self._send_json({"error": str(e)},status=HTTPStatus.BAD_REQUEST)
        elif path == "/toggle":
            try:
                rid = int(params.get("id","0"))
                ok = fw.toggle_rule(rid)
                self._send_json({"toggled": ok})
            except Exception as e:
                self._send_json({"error": str(e)},status=HTTPStatus.BAD_REQUEST)
        elif path == "/conflicts":
            data = fw.detect_conflicts()
            self._send_json(data)
        else:
            self._send_json({"error": f"Невідома кінцева точка {path}"},status=HTTPStatus.NOT_FOUND)


def start_http_server(firewall: Firewall,host: str = "127.0.0.1",port: int = 8080) -> threading.Thread:


    def server_thread() -> None:
        FirewallHTTPHandler.firewall = firewall
        httpd = HTTPServer((host,port),FirewallHTTPHandler)
        print(f"[Брандмауер] HTTP API слухає на http://{host}:{port}")
        httpd.serve_forever()

    thread = threading.Thread(target=server_thread,daemon=True)
    thread.start()
    return thread


def interactive_console(firewall: Firewall) -> None:

    MENU = """
Доступні дії:
 1. Показати правила
 2. Додати правило
 3. Видалити правило
 4. Перемкнути правило (увімкнути/вимкнути)
 5. Виявити дублікати/конфлікти
 6. Симулювати пакет
 7. Пошук у журналах
 8. Вийти
Введіть вибір:  """
    while True:
        try:
            choice = input(MENU).strip()
        except (EOFError,KeyboardInterrupt):
            print("\nВихід з інтерактивної консолі.")
            break
        if choice == "1":
            rules = firewall.get_rules()
            if not rules:
                print("Правила не визначені.")
            else:
                print("Поточні правила:")
                for rule in rules:
                    status = "ENABLED" if rule.enabled else "DISABLED"
                    print(
                        f"  ID {rule.id}: src_ip={rule.src_ip or '*'}, "
                        f"dest_ip={rule.dest_ip or '*'}, src_port={rule.src_port or '*'}, "
                        f"dest_port={rule.dest_port or '*'}, protocol={rule.protocol or '*'}, "
                        f"action={rule.action}, {status}"
                    )
        elif choice == "2":
            print("Визначте нове правило (натисніть Enter, щоб залишити поле порожнім)")
            src_ip = input(" IP-адреса джерела: ").strip() or None
            dest_ip = input(" IP-адреса призначення: ").strip() or None
            try:
                src_port_in = input(" Порт джерела: ").strip()
                src_port = int(src_port_in) if src_port_in else None
                dest_port_in = input(" Порт призначення: ").strip()
                dest_port = int(dest_port_in) if dest_port_in else None
            except ValueError:
                print("Неправильний номер порту.")
                continue
            protocol = input(" Протокол (TCP/UDP): ").strip().upper() or None
            action = input(" Дія (ALLOW/DENY): ").strip().upper() or "DENY"
            rule = firewall.add_rule(
                src_ip=src_ip,
                dest_ip=dest_ip,
                src_port=src_port,
                dest_port=dest_port,
                protocol=protocol,
                action=action,
            )
            print(f"Додано правило з ID {rule.id}.")
        elif choice == "3":
            rid = input("Введіть ID правила для видалення: ").strip()
            if rid.isdigit():
                ok = firewall.remove_rule(int(rid))
                print("Видалено." if ok else "Правило не знайдено.")
            else:
                print("Неправильний ID.")
        elif choice == "4":
            rid = input("Введіть ID правила для перемикання: ").strip()
            if rid.isdigit():
                ok = firewall.toggle_rule(int(rid))
                print("Перемкнено." if ok else "Правило не знайдено.")
            else:
                print("Неправильний ID.")
        elif choice == "5":
            conflicts = firewall.detect_conflicts()
            if not conflicts["duplicates"] and not conflicts["conflicts"]:
                print("Дублікатів або конфліктів не виявлено.")
            else:
                if conflicts["duplicates"]:
                    print("Дубльовані правила:")
                    for pair in conflicts["duplicates"]:
                        print(f"  {pair[0]} та {pair[1]}")
                if conflicts["conflicts"]:
                    print("Конфліктні правила:")
                    for pair in conflicts["conflicts"]:
                        print(f"  {pair[0]} та {pair[1]}")
        elif choice == "6":
            print("Симулювати один пакет")
            src_ip = input(" IP-адреса джерела: ").strip() or None
            dest_ip = input(" IP-адреса призначення: ").strip() or None
            try:
                src_port_in = input(" Порт джерела: ").strip()
                src_port = int(src_port_in) if src_port_in else None
                dest_port_in = input(" Порт призначення: ").strip()
                dest_port = int(dest_port_in) if dest_port_in else None
            except ValueError:
                print("Неправильний номер порту.")
                continue
            protocol = input(" Протокол (TCP/UDP): ").strip().upper() or None
            packet = {
                "src_ip": src_ip,
                "dest_ip": dest_ip,
                "src_port": src_port,
                "dest_port": dest_port,
                "protocol": protocol,
            }
            result = firewall.process_packet(packet)
            print(f"Результат для пакета: {result}")
        elif choice == "7":
            print("Пошук у журналах відхилених пакетів (залиште порожнім, щоб ігнорувати критерій)")
            src_ip = input(" IP-адреса джерела: ").strip() or None
            dest_ip = input(" IP-адреса призначення: ").strip() or None
            protocol = input(" Протокол: ").strip() or None
            results = firewall.search_logs(src_ip=src_ip,dest_ip=dest_ip,protocol=protocol)
            if not results:
                print("Відповідних записів у журналі не знайдено.")
            else:
                for entry in results:
                    ts = entry["timestamp"]
                    rid = entry["rule_id"]
                    reason = entry["reason"]
                    pkt = entry["packet"]
                    print(f"{ts} | rule {rid} | {reason} | {pkt}")
        elif choice == "8":
            print("Вихід.")
            break
        else:
            print("Невідомий вибір. Будь ласка, виберіть 1-8.")


def main() -> None:

    firewall = Firewall()

    start_http_server(firewall)

    print("\nЛаскаво просимо до простого сервісу брандмауера.\n")
    print(
        "Невеликий HTTP API доступний за адресою http://127.0.0.1:8080 для віддаленого "
        "керування правилами. Використовуйте консоль нижче для інтерактивного керування "
        "правилами та перегляду журналів.")
    interactive_console(firewall)


if __name__ == "__main__":
    main()