import os         # para poder ejecutar comandos en el sistema operativo
import sys        # para gestionar las salidas del script
import subprocess # para ejecutar comandos del sistema de forma más segura
import re         # para usar expresiones regulares

# comprobamos que el script se esté ejecutando como root
if os.geteuid() != 0:  # 0 es el UID de root 
    print("\033[93m[!]\033[0m Este script necesita permisos de superusuario. Ejecutalo con sudo.")
    sys.exit(1)


# -------- colores para los mensajes  --------
def titulo(msg):
    print("\n\033[95m" + msg + "\033[0m")
    
def ok(msg):
    print("\033[92m[OK]\033[0m " + msg)

def error(msg):
    print("\033[91m[ERROR]\033[0m " + msg)

def aviso(msg):
    print("\033[93m[!]\033[0m " + msg)

def info(msg):
    print("\033[94m[INFO]\033[0m " + msg)

def riesgo(msg):
    print("\033[91mRIESGO:\033[0m " + msg)

def recomendacion(msg):
    print("\033[96mRECOMENDACION:\033[0m " + msg)



# ---------------- SSH ----------------
def analizar_ssh():
    titulo("----· Analizando la configuración de SSH ·----")

    try:
        # abrimos el archivo de configuracion de SSH y lo leemos
        with open("/etc/ssh/sshd_config", "r") as f:
            lineas = f.readlines()

        login_root = None
        pwd_aut = None
        puerto_ssh = "22"  # el puerto por defecto de ssh

        for linea in lineas:
            # para eliminar comentarios y espacios durante la lectura:
            linea = linea.split("#", 1)[0].strip()
            if linea == "":
                continue # saltar las lineas que esten vacias

            # convertimos la linea obtenida a minusculas para mejor deteccion
            if linea.lower().startswith("permitrootlogin"):
                login_root = linea.split()[1]  # esto obtiene el valor yes (activado) o no (desactivado)

            if linea.lower().startswith("passwordauthentication"):
                pwd_aut = linea.split()[1]  # esto obtiene el valor yes o no

            if linea.lower().startswith("port"):
                puerto_ssh = linea.split()[1]  # esto obtiene el puerto configurado

        # -------- RESULTADOS --------

        # comprobamos el acceso de root por SSH
        if login_root == "yes":
            aviso("Root login habilitado")
            riesgo("Permite acceso directo como root por SSH")
            recomendacion("Deshabilitar PermitRootLogin\n")
        elif login_root == "no":
            ok("El login con Root está deshabilitado\n")
        else:
            info("No se encontró configuración de PermitRootLogin\n")

        # comprobamos la autenticacion por contraseña
        if pwd_aut == "yes":
            aviso("Autenticación por contraseña habilitada")
            riesgo("Vulnerabilidad ante ataques de fuerza bruta")
            recomendacion("Usar autenticación por clave pública\n")
        elif pwd_aut == "no":
            ok("La autenticación por contraseña está deshabilitada\n")
        else:
            info("No se encontró configuración de autenticacion por contraseña\n")

        # comprobamos el puerto de SSH
        if puerto_ssh == "22":
            aviso("Puerto SSH por defecto (22)")
            riesgo("Más expuesto a escaneos automáticos")
            recomendacion("Cambiar el puerto SSH\n")
        else:
            ok(f"El puerto SSH está modificado ({puerto_ssh})\n")

    except Exception as error_detectado:
        error(f"No se pudo leer sshd_config: {error_detectado}\n")  # mostramos el error detectado


# ---------------- FIREWALL ----------------
def analizar_firewall():
    titulo("----· Analizando el firewall ·----")

    # para comprobar si ufw (firewall de ubuntu) esta innactivo o activo
    # ejecutamos "ufw status"
    p1 = subprocess.run(["ufw", "status"], capture_output=True, text=True)
    salida = p1.stdout.lower() # convertimos a minusculas

    if "inactive" in salida:
        aviso("Firewall desactivado")
        riesgo("Sistema expuesto a conexiones no controladas")
        recomendacion("Activar el firewall (ufw enable)\n")
    else:
        ok("El firewall está activo\n")


# ---------------- PUERTOS ----------------
# diccionario de puertos comunes
def identificar_servicio(puerto):
    servicios_comunes = {
        "21": "FTP",
        "22": "SSH",
        "23": "TELNET",
        "25": "SMTP",
        "53": "DNS",
        "67": "DHCP",
        "68": "DHCP",
        "80": "HTTP",
        "110": "POP3",
        "139": "NETBIOS",
        "143": "IMAP",
        "443": "HTTPS",
        "445": "SMB",
        "3306": "MYSQL",
        "8080": "HTTP_2",
    }
    return servicios_comunes.get(puerto, "DESCONOCIDO")

def puerto_abierto_ufw(puerto):
    # devuelve True si el puerto está permitido por ufw (allow)
    try:
        # Ejecutamos "ufw status" y dividimos la salida en lineas
        status = subprocess.run(["ufw", "status"], capture_output=True, text=True).stdout.splitlines()
        for linea in status:
            # para buscar el puerto exacto y la palabra ALLOW en la misma linea
            if re.search(rf"\b{re.escape(puerto)}\b", linea) and re.search(r"ALLOW", linea, re.IGNORECASE):
                return True
        return False
    except:
        return False

# lista de puertos SSH alternativos permitidos
puertos_ssh = ["122", "322", "422"]

def analizar_puertos():
    titulo("----· Analizando los puertos abiertos ·----")

    try:
        # ejecutamos "ss -tuln" para ver los puertos abiertos
        salida = subprocess.run(["ss", "-tuln"], capture_output=True, text=True).stdout.splitlines()
        puertos_detectados = set() # "set" es para evitar duplicados

        for linea in salida[1:]:  # para saltarnos la cabecera cuando recorremos la salida
            # buscamos un numero de puerto despues de ':'
            match = re.search(r':(\d+)\b', linea) 
            if match:
                puerto = match.group(1)
                puertos_detectados.add(puerto)

        if not puertos_detectados:
            ok("No hay puertos abiertos detectados\n")
            return
        
        #creamos una tabla para la salida
        print("PUERTO   |    SERVICIO    |  ACCESIBLE")
        print("--------------------------------------")
        # ordenamos los puertos de menor a mayor
        for p in sorted(puertos_detectados, key=int):
            servicio = identificar_servicio(p)
            accesible = "SI" if puerto_abierto_ufw(p) else "NO, filtered"
            print(f"{p:<8} {servicio:<15} {accesible}") # mostramos la fila

            # avisos
            # permitimos los 3 puertos indicados y los que se añadan en la variable "puertos_ssh"
            if p not in ["22", "80", "443", *puertos_ssh]:
                if accesible == "SI":
                    aviso(f"Puerto {p} abierto y accesible")
                    riesgo(f"Puerto innecesario expuesto: {p}")
                    recomendacion(f"Cerrar o filtrar el puerto {p}")
            # analizamos el ftp tambien, ya que es inseguro por defecto
            if p == "21" and accesible == "SI":
                aviso("FTP está abierto")
                riesgo("Transmisiones sin cifrar")

        print()
        aviso("Revisar que solo estén abiertos los puertos necesarios\n")

    except Exception as error_detectado:
        error(f"No se pudieron analizar los puertos: {error_detectado}")


# ---------------- FTP ----------------
def analizar_ftp():
    titulo("----· Analizando el servicio FTP ·----")

    try:
    # para comprobar si el servicio vsftpd (servidor para ftp) estaá activo
        res = subprocess.run(["systemctl", "is-active", "vsftpd"], capture_output=True, text=True)
        # si esta activo, revisamos su configuracion
        if res.returncode == 0 and "active" in res.stdout:
            aviso("Servicio FTP activo")
            riesgo("FTP transmite datos sin cifrar")
            recomendacion("Deshabilitar el FTP o usar SFTP\n")

            try:
                # revisamos la configuracion de ftp
                with open("/etc/vsftpd.conf", "r") as f:
                    config = f.read()
                    if "anonymous_enable=YES" in config: # comprobamos el acceso anónimo
                        aviso("Acceso anónimo FTP habilitado")
                        riesgo("Acceso sin autenticación al sistema")
                        recomendacion("Deshabilitar anonymous_enable\n")
                    else:
                        ok("El acceso anónimo por FTP está deshabilitado\n")
            except:
                info("No se pudo verificar la configuración de FTP\n")
        else:
            ok("El servicio FTP no está activo\n")
    except Exception as error_detectado:
        error(f"Error comprobando FTP: {error_detectado}\n")


# ---------------- USUARIOS ----------------
def analizar_usuarios():
    titulo("----· Analizando los usuarios con UID 0 ·----")

    usuarios_uid0 = []

    # se revisa el archivo passwd; si un usuario tiene UID = 0, significa que tiene privilegios de root
    with open("/etc/passwd", "r") as f:
        for line in f:
            if ":0:" in line:
                usuario = line.split(":")[0] # separamos el usuario del su id
                usuarios_uid0.append(usuario)

    # si solo lo tiene root, es correcto
    if usuarios_uid0 == ["root"]:
        ok("Solo el usuario root tiene UID 0\n")
    else:
        aviso("Usuarios con UID 0 detectados:")
        for u in usuarios_uid0:
            if u != "root":
                print(f"   - {u}")
        riesgo("Usuarios adicionales con privilegios de root")
        recomendacion("\n- Cambiar los permisos de los usuarios\n- Eliminar el usuario\n- Bloquear su inicio de sesion")


# ---------------- CONTRASEÑAS ----------------
def analizar_contraseñas():
    titulo("----· Analizando los usuarios sin contraseña ·----")

    try:
        # para buscar usuarios con el campo de contraseña vacio en /etc/shadow
        # separamos por ":" y buscamos el segundo campo (contraseña) que esté vacío
        salida = (os.popen("awk -F: '($2==\"\"){print $1}' /etc/shadow").read().splitlines())

        if salida:
            aviso("Usuarios sin contraseña detectados:")
            #imprimimos los usuarios sin contraseña
            for usuario in salida:
                print(f"   - {usuario}")
            riesgo("Accesos sin autenticación y no autorizados")
            recomendacion("Establecer contraseñas seguras\n")
        else:
            ok("No se detectó ningún usuario sin contraseña\n")

    except:
        error("No se pudo analizar el archivo /etc/shadow\n")


# ---------------- ejecucion de las funciones ----------------
def run_auditoria():
    titulo("|=======================|\n|    AUDITORÍA DE SEGURIDAD    |\n|=======================|\n")

    analizar_ssh()
    analizar_firewall()
    analizar_puertos()
    analizar_ftp()
    analizar_usuarios()
    analizar_contraseñas()

    titulo("|=====================|\n|     AUDITORÍA FINALIZADA     |\n|=====================|\n")

run_auditoria()
