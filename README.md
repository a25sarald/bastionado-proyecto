
# Herramienta de auditoría y bastionado en Linux

## Descripción
Este repositorio contiene los scripts utilizados para la auditoría, bastionado y generación del informe final en un sistema Linux, concretamente un Ubuntu Server 22.04.  
Forman parte del proyecto de la 2ª evaluación de la asignatura *Bastionado de Redes y Sistemas Informáticos* en la especialización de Ciberseguridad de IT.

## Contenidos

### auditoria.py
Analiza el sistema y detecta configuraciones inseguras:
- SSH (root login, autenticación por contraseña, puerto)
- Firewall
- Puertos abiertos
- FTP
- Usuarios con UID 0
- Usuarios sin contraseña

### bastionado.py
Aplica las medidas de seguridad necesarias, según lo que se escoja en el menú, como:
- Deshabilitar root login
- Desactivar autenticación por contraseña
- Cambiar puerto SSH
- Activar firewall
- Cerrar puertos innecesarios
- Deshabilitar FTP
- Bloquear usuarios con UID 0 no autorizados
- Forzar contraseñas seguras
- Actualizar el sistema

Este script registra todas las acciones en: `/var/log/bastionado.log`

### informe.py
Genera un informe final en texto a partir del archivo de logs que contiene:
- Fecha y hora de creación
- OK (configuraciones correctas)
- AVISOS
- RIESGOS
- RECOMENDACIONES
- ERRORES

El informe se guarda en la carpeta donde se genere el script como `informe_bastionado.txt`.

## Requisitos del sistema
- Ser Linux (Ubuntu, Debian, Kali…)
- Tener Python 3
- Permisos de superusuario (sudo)

### Servicios y herramientas necesarias
- SSH
- UFW (firewall)
- systemctl
- ss (para detección de puertos)
- awk (para análisis de contraseñas)
- vsftpd (para FTP)

## Uso

### 1. Auditoría
```
sudo python3 auditoria.py
```

### 2. Bastionado
```
sudo python3 bastionado.py
```

### 3. Generación del informe
```
sudo python3 informe.py
```

## Archivos generados
- `/var/log/bastionado.log` : registro completo del bastionado  
- `informe_bastionado.txt` : informe final, estructurado  
