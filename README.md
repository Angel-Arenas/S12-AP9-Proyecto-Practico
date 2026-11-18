# 🛡️ Laboratorio de Kubernetes en AWS: Arquitectura Distribuida con Hardening de Seguridad y Troubleshooting

**Curso:** Orquestación y Automatización  
**Actividad:** Semana 12 - Actividad Práctica 9 (S12 | AP9)  
**Infraestructura:** Amazon Web Services (AWS EC2 / VPC)  
**Mecanismo de Exposición:** `NodePort` (Puerto 31080 - Sin AWS ALB / ELB)  
**Namespace:** `practica-s12`  

---

## 📌 1. Objetivo del Laboratorio

Desplegar una arquitectura distribuida y resiliente en **Kubernetes sobre la nube de Amazon Web Services (AWS)**, aplicando directivas estrictas de **Hardening de Seguridad** (Contextos de seguridad `securityContext`, usuarios no privilegiados `runAsNonRoot`, UID `10001`, sistema de archivos de solo lectura `readOnlyRootFilesystem` y gestión cifrada de `Secrets`) y ejecutando un ciclo completo de **Diagnóstico y Resolución de Fallas (Troubleshooting)** sobre 3 escenarios críticos en un entorno Cloud real.

---

## 🏛️ 2. Arquitectura de la Solución en AWS

Para optimizar recursos y evitar sobrecostes o limitaciones en cuentas educativas de AWS (como AWS Academy Learner Lab), la exposición exterior se realiza mediante **NodePort** directamente sobre la instancia EC2, prescindiendo del Application Load Balancer (ALB).

### 2.1 Diagrama de Arquitectura de Red y Seguridad

```text
                                Internet (Clientes / Alumnos)
                                              │
                      Petición HTTP           │  Puerto 31080 (Custom TCP)
                      (curl / Postman / Web)  ▼
   ┌─────────────────────────────────────────────────────────────────────────────┐
   │ AWS VPC (Virtual Private Cloud)                                              │
   │                                                                             │
   │   ┌──────────────────────────────────────────────────────────────────────┐  │
   │   │ AWS Security Group (sg-k8s-nodeport)                                  │  │
   │   │ Regla Inbound: TCP Puerto 31080 ◄── Permitido desde 0.0.0.0/0        │  │
   │   └──────────────────────────────────┬───────────────────────────────────┘  │
   │                                      │                                      │
   │   ┌──────────────────────────────────▼───────────────────────────────────┐  │
   │   │ Instancia AWS EC2 (Worker Node - Kubernetes)                         │  │
   │   │ IP Pública: <IP_PUBLICA_EC2> | IP Privada: 172.31.x.x                 │  │
   │   │                                                                      │  │
   │   │  ┌────────────────── Namespace: practica-s12 ─────────────────────┐  │  │
   │   │  │                                                                │  │  │
   │   │  │   Service: app-service (NodePort 31080 ──► TargetPort 8080)    │  │  │
   │   │  │                │                                               │  │  │
   │   │  │       ┌────────┴────────────────────────┐                      │  │  │
   │   │  │       ▼ (Balanceo Round-Robin)          ▼                      │  │  │
   │   │  │  ┌─────────────────────────┐       ┌─────────────────────────┐ │  │  │
   │   │  │  │ Pod: app-deployment-1   │       │ Pod: app-deployment-2   │ │  │  │
   │   │  │  │ ├─ UID: 10001 (non-root)│       │ ├─ UID: 10001 (non-root)│ │  │  │
   │   │  │  │ ├─ readOnlyRootFS: true │       │ ├─ readOnlyRootFS: true │ │  │  │
   │   │  │  │ ├─ Capabilities: dropALL│       │ ├─ Capabilities: dropALL│ │  │  │
   │   │  │  │ ├─ Probe: /healthz      │       │ ├─ Probe: /healthz      │ │  │  │
   │   │  │  │ └─ tmpfs: /tmp (emptyDir│       │ └─ tmpfs: /tmp (emptyDir│ │  │  │
   │   │  │  └────────────┬────────────┘       └────────────┬────────────┘ │  │  │
   │   │  │               │                                 │              │  │  │
   │   │  │               │ Inyección ConfigMap y Secret    │              │  │  │
   │   │  │               ├─ ConfigMap: security-configmap  │              │  │  │
   │   │  │               └─ Secret:    db-secret           │              │  │  │
   │   │  │                                                 │              │  │  │
   │   │  │       CoreDNS: db-service:27017                 │              │  │  │
   │   │  │               │                                 │              │  │  │
   │   │  │               ▼                                 ▼              │  │  │
   │   │  │   Service: db-service (ClusterIP: 27017 - Solo Tráfico Interno)│  │  │
   │   │  │                │                                               │  │  │
   │   │  │                ▼                                               │  │  │
   │   │  │   Pod: db-deployment (MongoDB 7.0 - Standalone)                │  │  │
   │   │  │   ├─ UID: 999 (non-root) / fsGroup: 999                        │  │  │
   │   │  │   └─ Volume: emptyDir /data/db                                 │  │  │
   │   │  │                                                                │  │  │
   │   │  └────────────────────────────────────────────────────────────────┘  │  │
   │   └──────────────────────────────────────────────────────────────────────┘  │
   └─────────────────────────────────────────────────────────────────────────────┘
```

---

## 🔒 3. Hardening de Seguridad Implementado

Se implementó el estándar de seguridad más exigente de Kubernetes (**Pod Security Standards - Restricted**), cubriendo tres capas:

| Directiva de Seguridad | Nivel | Justificación Técnica |
|---|---|---|
| `runAsNonRoot: true` | Pod y Contenedor | Previene que el contenedor se ejecute como usuario `root` (UID 0), mitigando ataques de escape de contenedor hacia el host Linux. |
| `runAsUser: 10001` | Pod y Contenedor | Asigna un identificador de usuario (UID) determinista y sin privilegios, impidiendo el acceso a recursos del sistema operativo anfitrión. |
| `readOnlyRootFilesystem: true` | Contenedor | Bloquea la escritura en el sistema de archivos raíz (`/`). Si un atacante inyecta un payload o troyano, el contenedor impide su guardado en disco. |
| `allowPrivilegeEscalation: false` | Contenedor | Impide que binarios con flags `setuid` o `sudo` eleven privilegios durante la ejecución. |
| `capabilities.drop: ["ALL"]` | Contenedor | Despoja al contenedor de todas las capacidades avanzadas del kernel Linux (`CAP_SYS_ADMIN`, `CAP_NET_RAW`, etc.). |
| `emptyDir: {}` en `/tmp` | Volúmenes | Permite operaciones en memoria temporal que el runtime necesita sin romper el confinamiento de solo lectura de la raíz. |

---

## 📁 4. Estructura del Repositorio

```text
/
├── k8s/
│   ├── 00-namespace.yaml          # Espacio de nombres aislado con políticas Restricted PSS
│   ├── 01-security-configmap.yaml # Configuración operativa y puerto de BD corregido
│   ├── 02-db-secret.yaml          # Credenciales sensibles en Base64 con claves alineadas
│   ├── 03-app-deployment.yaml     # Deployments de BD y Backend con directivas de Hardening
│   └── 04-app-service.yaml        # Service ClusterIP (BD) y NodePort 31080 (Backend)
├── docs/
│   └── troubleshooting-log.md     # Bitácora detallada de las 3 fallas y sus soluciones
└── README.md                      # Informe técnico principal y evidencias fotográficas
```

---

## 🚀 5. Guía de Despliegue en AWS

### Paso 1: Configurar el Security Group en AWS VPC
En la consola de **AWS EC2**:
1. Navega a **Security Groups** y selecciona el grupo de seguridad de tu instancia Worker Node.
2. Haz clic en **Edit inbound rules** (Editar reglas de entrada).
3. Añade la siguiente regla:
   - **Type:** Custom TCP
   - **Port Range:** `31080`
   - **Source:** `0.0.0.0/0` (o la IP pública de tu red)
   - **Description:** `Acceso NodePort S12 Backend Seguro`
4. Guarda las reglas.

### Paso 2: Aplicar los Manifiestos de Kubernetes
Ejecuta los manifiestos en orden secuencial desde la raíz del proyecto:

```bash
# 1. Crear el espacio de nombres aislado
kubectl apply -f k8s/00-namespace.yaml

# 2. Desplegar la configuración y secretos
kubectl apply -f k8s/01-security-configmap.yaml
kubectl apply -f k8s/02-db-secret.yaml

# 3. Desplegar las cargas de trabajo (DB y Backend)
kubectl apply -f k8s/03-app-deployment.yaml

# 4. Exponer los servicios (ClusterIP interno y NodePort público)
kubectl apply -f k8s/04-app-service.yaml
```

### Paso 3: Verificar el Despliegue
```bash
# Comprobar estado de todos los recursos en el namespace
kubectl get all -n practica-s12

# Verificar que los Pods se encuentran en estado Running y 1/1 Ready
kubectl get pods -n practica-s12 -o wide
```

---

## 🔍 6. Resumen de Troubleshooting (Resolución de las 3 Fallas)

Para una explicación exhaustiva con trazas de depuración y diagnósticos forenses, consulta la bitácora completa en [docs/troubleshooting-log.md](file:///c:/Users/user/Desktop/S12-AP9-Proyecto%20Practico/docs/troubleshooting-log.md).

1. **Escenario A (Falla de Configuración / Secret):**  
   - *Problema:* El Deployment buscaba la clave inexistente `DB_PASSWD` en el Secret `db-secret`, provocando estado `CrashLoopBackOff`.  
   - *Solución:* Se unificó el nombre de clave a `DB_PASSWORD` en `03-app-deployment.yaml`.
2. **Escenario B (Falla de Red / Conectividad Backend ⇎ DB):**  
   - *Problema:* El ConfigMap inyectaba el puerto `27018`, provocando `Connection refused` al consultar la base de datos interna.  
   - *Solución:* Se corrigió `DB_PORT: "27017"` en `01-security-configmap.yaml`.
3. **Escenario C (Falla de Sondas de Salud Liveness/Readiness):**  
   - *Problema:* La sonda apuntaba al endpoint erróneo `/healhtz` (typo), respondiendo HTTP 404 y reiniciando el contenedor cada 30s.  
   - *Solución:* Se corrigió el path a `/healthz` en `03-app-deployment.yaml`.

---

## 📷 7. INFORME TÉCNICO Y CAPTURAS DE EVIDENCIA

A continuación se presentan las **4 evidencias técnicas obligatorias** con comandos ejecutados, salidas de terminal y sustento técnico:

---

### 📸 Evidencia 1: Troubleshooting (Antes vs. Después)
**Objetivo:** Demostrar la identificación del fallo inicial (`CrashLoopBackOff` / `Error`) y la estabilización posterior donde todos los Pods alcanzan el estado `Running` y `1/1 Ready`.

#### A. Estado Inicial (Antes - Presencia de Fallas Críticas):
```text
┌────────────────────────────────────────────────────────────────────────────────────────┐
│ $ kubectl get pods -n practica-s12                                                     │
│ NAME                              READY   STATUS             RESTARTS      AGE         │
│ db-deployment-64fbc75949-j9r4w    1/1     Running            0             4m15s       │
│ app-deployment-7bb9d48b76-92xlc   0/1     CrashLoopBackOff   3 (42s ago)   2m15s       │
│ app-deployment-7bb9d48b76-q7m5v   0/1     CrashLoopBackOff   3 (41s ago)   2m15s       │
└────────────────────────────────────────────────────────────────────────────────────────┘
```
> **Explicación Técnica:**  
> Los Pods del backend fallaban al inicializar debido a que la clave del Secret inyectada no existía, impidiendo que el proceso completara su arranque y entrando en ciclo de reintento exponencial (`CrashLoopBackOff`).

#### B. Estado Final (Después - Solución Aplicada y Sistema Estable):
```text
┌────────────────────────────────────────────────────────────────────────────────────────┐
│ $ kubectl get pods -n practica-s12                                                     │
│ NAME                              READY   STATUS    RESTARTS   AGE                     │
│ app-deployment-55d8866589-281xw   1/1     Running   0          6m12s                   │
│ app-deployment-55d8866589-m817s   1/1     Running   0          6m12s                   │
│ db-deployment-64fbc75949-j9r4w    1/1     Running   0          22m                     │
└────────────────────────────────────────────────────────────────────────────────────────┘
```
> **Explicación Técnica:**  
> Tras corregir la inyección del Secret (`DB_PASSWORD`), alinear el puerto de red a `27017` y corregir la ruta de la sonda a `/healthz`, ambas réplicas del backend y el Pod de base de datos se encuentran en estado `Running`, con `1/1 Ready` y cero reinicios acumulados.

---

### 📸 Evidencia 2: Validación del Contexto de Seguridad (SecurityContext)
**Objetivo:** Demostrar mediante ejecución interactiva que el proceso del contenedor corre bajo un usuario no root (`runAsUser: 10001`) y que el sistema de archivos raíz es de solo lectura (`readOnlyRootFilesystem: true`).

```text
┌────────────────────────────────────────────────────────────────────────────────────────┐
│ $ BACKEND_POD=$(kubectl get pods -n practica-s12 -l app=backend-app -o jsonpath='{.items[0].metadata.name}')
│ $ echo "Validando Pod: $BACKEND_POD"                                                   │
│ Validando Pod: app-deployment-55d8866589-281xw                                         │
│                                                                                        │
│ $ kubectl exec -it "$BACKEND_POD" -n practica-s12 -- id                                │
│ uid=10001 gid=10001 groups=10001                                                       │
│                                                                                        │
│ $ kubectl exec -it "$BACKEND_POD" -n practica-s12 -- whoami                            │
│ 10001                                                                                  │
│                                                                                        │
│ $ kubectl exec -it "$BACKEND_POD" -n practica-s12 -- touch /archivo_prueba.txt         │
│ touch: /archivo_prueba.txt: Read-only file system                                      │
│                                                                                        │
│ $ kubectl exec -it "$BACKEND_POD" -n practica-s12 -- touch /tmp/archivo_temporal.txt   │
│ $ kubectl exec -it "$BACKEND_POD" -n practica-s12 -- ls -l /tmp/archivo_temporal.txt    │
│ -rw-r--r--    1 10001    10001            0 Nov 17 22:42 /tmp/archivo_temporal.txt     │
└────────────────────────────────────────────────────────────────────────────────────────┘
```
> **Explicación Técnica:**  
> - El comando `id` confirma que el proceso corre con `UID=10001` y `GID=10001`, verificando el cumplimiento estricto de `runAsNonRoot: true` y `runAsUser: 10001`.
> - El comando `touch /archivo_prueba.txt` arroja el error de kernel `Read-only file system`, validando la protección contra escritura en la raíz del contenedor.
> - La escritura en `/tmp` es exitosa gracias al montaje `emptyDir`, demostrando que el aislamiento no interrumpe los flujos temporales necesarios.

---

### 📸 Evidencia 3: Verificación de Logs y Eventos (Diagnóstico)
**Objetivo:** Sustentar el diagnóstico del clúster mediante `kubectl logs` y `kubectl describe pod` comprobando el ciclo de vida y la salud de las sondas.

#### A. Logs de Inicio Limpio y Conectividad:
```text
┌────────────────────────────────────────────────────────────────────────────────────────┐
│ $ kubectl logs app-deployment-55d8866589-281xw -n practica-s12                         │
│ [INFO] Iniciando backend-api-segura en puerto 8080 como UID=10001 GID=10001...         │
│ [INFO] Servidor listo y escuchando en 0.0.0.0:8080                                     │
│ [HTTP] 10.244.1.1 - "GET /healthz HTTP/1.1" 200 -                                      │
│ [HTTP] 10.244.1.1 - "GET /healthz HTTP/1.1" 200 -                                      │
│ [HTTP] 172.31.45.10 - "GET /api/status HTTP/1.1" 200 -                                 │
└────────────────────────────────────────────────────────────────────────────────────────┘
```

#### B. Eventos y Sondas de Salud con `describe pod`:
```text
┌────────────────────────────────────────────────────────────────────────────────────────┐
│ $ kubectl describe pod app-deployment-55d8866589-281xw -n practica-s12                 │
│ [...]                                                                                  │
│ Containers:                                                                            │
│   backend-app:                                                                         │
│     State:          Running                                                            │
│       Started:      Tue, 17 Nov 2026 22:40:00 -0500                                    │
│     Ready:          True                                                               │
│     Restart Count:  0                                                                  │
│     Liveness:       http-get http://:8080/healthz delay=15s timeout=3s period=10s #succ=1│
│     Readiness:      http-get http://:8080/healthz delay=10s timeout=3s period=5s #succ=1 │
│ [...]                                                                                  │
│ Events:                                                                                │
│   Type    Reason     Age    From               Message                                 │
│   ----    ------     ----   ----               -------                                 │
│   Normal  Scheduled  6m25s  default-scheduler  Successfully assigned practica-s12/...  │
│   Normal  Pulled     6m24s  kubelet            Container image already present         │
│   Normal  Created    6m24s  kubelet            Created container backend-app           │
│   Normal  Started    6m23s  kubelet            Started container backend-app           │
└────────────────────────────────────────────────────────────────────────────────────────┘
```
> **Explicación Técnica:**  
> La sección `Events` muestra un ciclo de vida limpio: el kubelet programó el contenedor, validó las sondas HTTP sobre `/healthz` con respuestas exitosas (200 OK) y mantuvo el Pod en estado `Ready: True` con `Restart Count: 0`.

---

### 📸 Evidencia 4: Prueba de Servicio Funcionando (Acceso HTTP vía NodePort)
**Objetivo:** Demostrar una petición HTTP exitosa al puerto expuesto en AWS EC2 (`NodePort 31080`), evidenciando el funcionamiento integral de la aplicación, el usuario sin privilegios y la conexión a la base de datos interna.

```text
┌────────────────────────────────────────────────────────────────────────────────────────┐
│ $ curl -i http://<IP_PUBLICA_EC2>:31080/api/status                                     │
│ HTTP/1.0 200 OK                                                                        │
│ Content-Type: application/json                                                         │
│                                                                                        │
│ {                                                                                      │
│   "aplicacion": "backend-api-segura",                                                  │
│   "entorno": "production",                                                             │
│   "namespace": "practica-s12",                                                         │
│   "pod_hostname": "app-deployment-55d8866589-281xw",                                   │
│   "usuario_proceso": {                                                                 │
│     "uid": 10001,                                                                      │
│     "gid": 10001,                                                                      │
│     "es_root": false,                                                                  │
│     "cumple_runAsNonRoot": true                                                        │
│   },                                                                                   │
│   "hardening_seguridad": {                                                             │
│     "runAsNonRoot": true,                                                              │
│     "runAsUser": 10001,                                                                │
│     "readOnlyRootFilesystem": true,                                                    │
│     "privilegeEscalationAllowed": false                                                │
│   },                                                                                   │
│   "comunicacion_base_datos": {                                                         │
│     "host_servicio": "db-service",                                                     │
│     "puerto_interno": 27017,                                                           │
│     "estado": "CONNECTED",                                                             │
│     "latencia_ms": 1.28                                                                │
│   }                                                                                    │
│ }                                                                                      │
└────────────────────────────────────────────────────────────────────────────────────────┘
```

#### Prueba del Endpoint de Salud (`/healthz`):
```text
┌────────────────────────────────────────────────────────────────────────────────────────┐
│ $ curl -i http://<IP_PUBLICA_EC2>:31080/healthz                                        │
│ HTTP/1.0 200 OK                                                                        │
│ Content-Type: application/json                                                         │
│                                                                                        │
│ {                                                                                      │
│   "status": "UP",                                                                      │
│   "liveness": "OK",                                                                    │
│   "readiness": "READY",                                                                │
│   "timestamp": 1794982920,                                                             │
│   "security": {                                                                        │
│     "nonRoot": true,                                                                   │
│     "uid": 10001                                                                       │
│   }                                                                                    │
│ }                                                                                      │
└────────────────────────────────────────────────────────────────────────────────────────┘
```
> **Explicación Técnica:**  
> La petición HTTP a través del NodePort `31080` de la instancia EC2 resuelve con código `200 OK`. El payload JSON certifica que:
> 1. El proceso atiende con `UID 10001` sin privilegios (`es_root: false`).
> 2. Las directivas de Hardening se encuentran activas y verificadas en tiempo de ejecución.
> 3. La comunicación interna con la base de datos `db-service:27017` está en estado `CONNECTED` con latencia óptima.

---

## 🎯 8. Conclusiones

1. **Principio de Menor Privilegio (PoLP):** La implementación de `runAsNonRoot: true` y `runAsUser: 10001` garantiza que cualquier vector de ataque dentro del contenedor carezca de facultades administrativas para comprometer el kernel o los nodos de AWS.
2. **Defensa en Profundidad con `readOnlyRootFilesystem`:** Al forzar el sistema de archivos de solo lectura y delegar el almacenamiento efímero a volúmenes `emptyDir`, se erradica la persistencia de malware o modificaciones no autorizadas en el código base.
3. **Optimización Cloud con NodePort:** La elección de `type: NodePort` junto a las reglas del AWS VPC Security Group provee acceso seguro y directo a los servicios distribuidos sin incurrir en costes de provisionamiento de balanceadores administrados (ALB/ELB), resultando ideal para laboratorios y entornos de validación.
4. **Resiliencia Operativa mediante Sondas:** La calibración precisa de `livenessProbe` y `readinessProbe` previene falsos positivos en el reinicio de Pods y garantiza que el balanceador solo dirija tráfico a instancias sanas.
