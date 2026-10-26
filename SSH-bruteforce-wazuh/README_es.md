[🇬🇧 English](README.md)

# Detección de fuerza bruta SSH: Ataque con Hydra y detección con Wazuh

Práctica de laboratorio en la que se simula un ataque de fuerza bruta contra SSH con Hydra y se analiza cómo un SIEM correlaciona los eventos individuales de autenticación fallida en una alerta de ataque, documentado como un caso de triage de analista SOC L1.

---

## Mapeo MITRE ATT&CK

- **Tácticas:** Credential Access.
- **Técnicas:**
  - [T1110.001] Brute Force: Password Guessing (ataque de diccionario contra el servicio SSH con Hydra)
  - [T1078] Valid Accounts (intento de validación de credenciales de usuarios del sistema)

---

## 1. Entorno y Preparación

El laboratorio está formado por tres equipos en la misma red local, en adaptador puente:

| Equipo | Función | IP |
|---|---|---|
| Kali Linux (VirtualBox) | Atacante — lanza el ataque de fuerza bruta con Hydra | `192.168.18.155` |
| Ubuntu-lab (VirtualBox, agente Wazuh 4.14.7) | Víctima — servidor SSH objetivo del ataque | `192.168.18.54` |
| Wazuh manager (wazuh-manager) | SIEM — recibe y correlaciona los eventos | `192.168.18.113` |

![IP del atacante (Kali)](img/01-kali-ip.png)

*`ip -br addr` en Kali — confirma la IP de origen (192.168.18.155) que luego aparece en las alertas de Wazuh.*

En Ubuntu-lab, confirmar que el servicio SSH está activo:

```bash
sudo systemctl status ssh
```

En Kali, confirmar que Hydra está disponible:

```bash
which hydra || sudo apt install hydra -y
```

Crear las listas de prueba (simulan un diccionario básico de usuarios y contraseñas):

```bash
echo -e "jsmith\nadmin\nroot" > /tmp/users.txt
echo -e "123456\npassword\nadmin123\nwrongpass" > /tmp/pass.txt
```

---

## 2. Ejecución del Ataque

Desde Kali, contra el SSH de Ubuntu-lab:

```bash
hydra -L /tmp/users.txt -P /tmp/pass.txt ssh://192.168.18.54
```

![Ataque Hydra lanzado desde Kali](img/02-hydra-ataque.png)

*12 combinaciones probadas (3 usuarios × 4 contraseñas, todas las parejas posibles), ninguna válida.*

**Resultado:**

```
[DATA] attacking ssh://192.168.18.54:22
1 of 1 target completed, 0 valid password found
```

---

## 3. Detección en Wazuh

### Eventos individuales

Búsqueda en Threat Hunting:

```
agent.name: "Ubuntu-lab"
rule.groups: "authentication_failed"
```

![Eventos individuales de autenticación fallida](img/03-eventos-individuales.png)

*32 eventos en segundos, repartidos entre:*
- `rule.id: 5760` — *sshd: authentication failed* (usuario válido, contraseña incorrecta)
- `rule.id: 5710` — *Attempt to login using a non-existent user*
- `rule.id: 5557` — *unix_chkpwd: Password check failed*

### Alerta de correlación

```
rule.id: 5763
```

![Alerta de fuerza bruta correlacionada](img/04-alerta-correlacion.png)

*1 evento: "sshd: brute force trying to get access to the system. Authentication failed." — nivel 10, frente al nivel 5 de los eventos individuales.*

---

## 4. Informe de Incidente

| Campo | Detalle |
|---|---|
| Fecha/hora | 2026-10-25, 19:06:30 |
| Regla disparada | 5763 — brute force SSH |
| Severidad | 10 (alta) |
| IP origen | 192.168.18.155 |
| Sistema afectado | Ubuntu-lab |
| Evidencia previa | 32 eventos de autenticación fallida (reglas 5760 / 5710) en los segundos anteriores |
| Resultado del ataque | Sin éxito — 0 credenciales válidas encontradas |
| Acción recomendada | Bloqueo temporal de la IP origen; valorar Fail2Ban o una regla activa de respuesta en Wazuh para automatizar el bloqueo |

---

## 5. Conclusión

La correlación de eventos individuales (nivel 5) en una alerta de fuerza bruta (nivel 10) demuestra el valor de un SIEM frente a revisar logs sueltos: un evento aislado puede ser un simple error de usuario, pero el patrón agrupado por IP y por tiempo es lo que distingue un ataque real y justifica la escalada.

---

## 6. Próximos Pasos

- Configurar una regla de respuesta activa en Wazuh para bloquear automáticamente la IP tras la alerta 5763.
- Repetir el ejercicio con un diccionario que incluya la contraseña real, para documentar también el caso de compromiso exitoso.
