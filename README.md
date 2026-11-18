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
