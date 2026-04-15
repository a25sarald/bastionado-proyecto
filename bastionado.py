import os         # para poder ejecutar comandos en el sistema operativo
import shutil     # para copiar, mover o eliminar archivos de manera segura
import subprocess # para ejecutar comandos del sistema de forma mas segura
import re         # para usar expresiones regulares
from datetime import datetime # importamos la fecha y hora del sistema para registrarlas en los logs
PUERTO_SSH = "22"

# -------- logging --------
# ruta donde se van a guardar los logs de los cambios que se hagan
LOG_FILE = "/var/log/bastionado.log"

# elegimos el formato: fecha - hora - mensaje
def log(msg):
    with open(LOG_FILE, "a") as f:
        f.write(f"{datetime.now()} - {msg}\n")


# -------- colores para los mensajes  --------
def titulo(msg):
    print("\n\033[95m" + msg + "\033[0m")
    
def ok(msg):
    print("\033[92m[OK]\033[0m " + msg) # con esto le ponemos color al mensaje
    log(f"[OK] {msg}") # enviamos el mensaje al archivo de logs

def error(msg):
    print("\033[91m[ERROR]\033[0m " + msg)
    log(f"[ERROR] {msg}")

def aviso(msg):
    print("\033[93m[!]\033[0m " + msg)
    log(f"[AVISO] {msg}")

def info(msg):
    print("\033[94m[INFO]\033[0m " + msg)
    log(f"[INFO] {msg}")

def riesgo(msg):
    print("\033[91mRIESGO:\033[0m " + msg)
    log(f"[RIESGO] {msg}")

def recomendacion(msg):
    print("\033[96mRECOMENDACION:\033[0m " + msg)
    log(f"[RECOMENDACION] {msg}")


# ---------------- SSH ----------------
def bast_ssh():
    titulo("----· Bastionado de SSH ·----")
    ssh_conf = "/etc/ssh/sshd_config"             # ruta del archivo de configuracion ssh
    backup_conf = "/etc/ssh/sshd_config.bak"      # ruta de la copia de seguridad
    puertos_validos_ssh = ["122", "322", "422"]   # puertos alternativos permitidos
    try:
        # ----- copia de seguridad -----
        # antes de modificar la configuracion de SSH, hacemos un backup
        shutil.copy(ssh_conf, backup_conf)
        info(f"Backup creado en {backup_conf}")

        # leemos todo el archivo de configuracion
        with open(ssh_conf, "r") as f:
            config = f.read()

        # ---- login root ----
        # si PermitRootLogin esta habilitado, lo deshabilitamos
        if "PermitRootLogin yes" in config:
            subprocess.run(["sed", "-i", "s/^PermitRootLogin.*/PermitRootLogin no/", ssh_conf])
            aviso("Root login estaba habilitado")
            riesgo("Permite acceso directo como root por SSH")
            recomendacion("Deshabilitar PermitRootLogin")
            ok("Root login deshabilitado\n")
        else:
            ok("Root login ya estaba seguro\n")

        # ---- aut. contraseña ----
        # si la autenticacion por contraseña esta habilitada, la deshabilitamos
        if "PasswordAuthentication yes" in config:
            subprocess.run(["sed", "-i", "s/^PasswordAuthentication.*/PasswordAuthentication no/", ssh_conf])
            aviso("Autenticación por contraseña habilitada")
            riesgo("Vulnerable a ataques de fuerza bruta")
            recomendacion("Usar autenticación por clave pública")
            ok("Autenticación por contraseña deshabilitada\n")
        else:
            ok("La autenticación por contraseña ya es segura\n")

        # ---- puerto ----
        # cambiamos el puerto si está el predeterminado (22)
        # con esto se pueden reducir escaneos automaticos
        while True:
            aviso("Puerto SSH por defecto")
            riesgo("Más expuesto a escaneos automáticos")
            recomendacion(f"Cambiar el puerto SSH a uno nuevo")
            print(f"Puertos permitidos para SSH: {puertos_validos_ssh}")
            nuevo_puerto = input("Selecciona nuevo puerto SSH: ")
            if nuevo_puerto in puertos_validos_ssh:
                break
            else:
                error("Puerto no permitido. Intentalo de nuevo")

        # reemplazar o añadir la linea "Port" si no existe
        if "Port " in config:
            subprocess.run(["sed", "-i", f"s/^#\\?Port.*/Port {nuevo_puerto}/", ssh_conf])
        else:
            with open(ssh_conf, "a") as f:
                f.write(f"\nPort {nuevo_puerto}\n")

        # abrimos el nuevo puerto en el firewall
        subprocess.run(["ufw", "allow", nuevo_puerto])

        ok(f"Puerto SSH cambiado a {nuevo_puerto} y abierto en el firewall\n")

        # ajustamos los permisos del archivo de configuración para que solo root lo lea
        os.chmod(ssh_conf, 0o600)

        # reiniciaamos SSH para aplicar los cambios
        result = subprocess.run(["systemctl", "restart", "ssh"], capture_output=True)
        if result.returncode == 0:
            info("SSH reiniciado correctamente")
        else:
            error(f"No se pudo reiniciar SSH: {result.stderr.decode()}")

    except Exception as e:
        error(f"No se pudo bastionar el SSH: {e}")


# ---------------- FIREWALL ----------------
def bast_firewall():
    titulo("----· Bastionado del firewall ·----")
    try:
        # para comprobar si el firewall esta desactivado
        resultado = subprocess.run("ufw status | grep inactive", shell=True)
        if resultado.returncode == 0:
            aviso("El firewall está desactivado")
            riesgo("El sistema está expuesto a conexiones no controladas")
            recomendacion("Activar el firewall")
            # permitimos SSH antes de activar el ufw para no bloquear el acceso remoto del admin
            subprocess.run(["ufw", "allow", "ssh"])
            subprocess.run(["ufw", "--force", "enable"])
            ok("Firewall activado correctamente")
        else:
            ok("Firewall ya estaba activo")
    except Exception as e:
        error(f"No se pudo bastionar firewall: {e}")


# ---------------- PUERTOS ----------------
def cerrar_puertos_innecesarios():
    titulo("----· Cerrando puertos ·----")
    try:
        puertos_permitidos = [PUERTO_SSH, "22", "80", "443"] # puertos alternativos permitidos
        # obtenemos los puertos abiertos
        salida = subprocess.run(["ss", "-tuln"], capture_output=True, text=True).stdout

        puertos_detectados = set()
        # extraemos los puertos detectados
        for linea in salida.splitlines():
            match = re.search(r':(\d+)\s', linea)
            if match:
                puerto = match.group(1)
                puertos_detectados.add(puerto)

        print("\nPuertos detectados:", puertos_detectados)

        # analizamos cada puerto
        for puerto in puertos_detectados:
            if puerto not in puertos_permitidos:
                # revisamos si ya está bloqueado en el ufw
                status = subprocess.run(["ufw", "status", "numbered"], capture_output=True, text=True).stdout
                if puerto not in status:
                    subprocess.run(["ufw", "deny", puerto])
                    aviso(f"Puerto {puerto} abierto")
                    riesgo("Puerto innecesario expuesto")
                    recomendacion(f"Cerrar el puerto {puerto}")
                    ok(f"Puerto {puerto} bloqueado\n")
                else:
                    ok(f"El puerto {puerto} ya estaba bloqueado")
            else:
                ok(f"Puerto {puerto} permitido")

    except Exception as e:
        error(f"No se pudieron analizar los puertos: {e}")


# ---------------- FTP ----------------
def bast_ftp():
    titulo("----· Bastionado FTP ·----")
    try:
        # comprobamos si el servicio FTP esta activo
        resultado = subprocess.run(["systemctl", "is-active", "vsftpd"], capture_output=True)
        if resultado.returncode == 0:
            # detenemos y deshabilitamos el servicio
            subprocess.run(["systemctl", "stop", "vsftpd"])
            subprocess.run(["systemctl", "disable", "vsftpd"])
            aviso("El FTP está activo")
            riesgo("FTP transmite datos sin cifrar")
            recomendacion("Deshabilitar FTP o usar SFTP")
            ok("FTP desactivado")
        else:
            ok("FTP ya estaba desactivado")
    except Exception as e:
        error(f"No se pudo bastionar FTP: {e}")


# ---------------- USUARIOS ----------------
def bast_usuarios():
    titulo("----· Bastionado de usuarios UID 0 ·----")
    usuarios_uid0 = []

    try:
        # buscamos usuarios con UID 0 (privilegios de root)
        with open("/etc/passwd", "r") as f:
            for line in f:
                if ":0:" in line:
                    usuario = line.split(":")[0]
                    usuarios_uid0.append(usuario)
        
        for u in usuarios_uid0:    # bloqueamos cualquier usuario que no sea root
            if u != "root":
                aviso(f"Usuario con UID 0 detectado: {u}")
                riesgo("Usuario con privilegios de root no autorizado")
                recomendacion("Se bloqueará el acceso del usuario")

                # bloqueamos la contraseña
                res_passwd = subprocess.run(["passwd", "-l", u], capture_output=True, text=True)

                # impedimos el inicio de sesion
                res_shell = subprocess.run(["usermod", "-s", "/usr/sbin/nologin", u], capture_output=True, text=True)

                # comprobamos resultados
                if res_passwd.returncode == 0 and res_shell.returncode == 0:
                    ok(f"Usuario {u} bloqueado correctamente. No podrá iniciar sesión")
                else:
                    error(f"No se pudo bloquear completamente a {u}")
                    if res_passwd.stderr:
                        print(res_passwd.stderr)
                    if res_shell.stderr:
                        print(res_shell.stderr)

        if usuarios_uid0 == ["root"]:
            ok("Solo root tiene UID 0\n")

    except Exception as e:
        error(f"No se pudieron bastionar los usuarios: {e}")


# ---------------- CONTRASEÑAS ----------------
def bast_contraseñas():
    titulo("----· Bastionado de contraseñas ·----")
    try:
        # buscamos usuarios sin contraseña (con el campo vacio)
        # $1 es el campo del nombre de usuairo, y $2 el de contraseña
        salida = subprocess.run("awk -F: '($2==\"\"){print $1}' /etc/shadow", shell=True, capture_output=True, text=True).stdout.splitlines()
        if salida:
            for usuario in salida:
                aviso(f"Usuario {usuario} sin contraseña")
                riesgo("Acceso sin autenticación")
                recomendacion("Establecer contraseña segura")
                # si hay usuarios sin contraseña, obligamos a poner una
                subprocess.run(["passwd", usuario])
                ok(f"Contraseña establecida para {usuario}")
        else:
            ok("No hay usuarios sin contraseña")
    except Exception as e:
        error(f"No se pudo bastionar contraseñas: {e}")


# ---------------- ACTUALIZAR ----------------
def actualizar_sistema():
    titulo("----· Actualizando sistema ·----")
    try:
        # actualizamos los repositorios y paquetes
        subprocess.run(["apt", "update"])
        subprocess.run(["apt", "upgrade", "-y"])
        ok("\nSistema actualizado")
    except Exception as e:
        error(f"No se pudo actualizar el sistema: {e}")


# ---------------- MENU ----------------
def menu_bastionado():
    while True:
        titulo("|======================|\n|      MODO DE BASTIONADO      |\n|======================|")

        print("1. Bastionar SSH")
        print("2. Firewall")
        print("3. Puertos")
        print("4. FTP")
        print("5. Usuarios")
        print("6. Contraseñas")
        print("7. Actualizar sistema")
        print("8. Salir\n")

        opcion = input("---· Selecciona una opción: ")

        if opcion == "1":
            bast_ssh()
        elif opcion == "2":
            bast_firewall()
        elif opcion == "3":
            cerrar_puertos_innecesarios()
        elif opcion == "4":
            bast_ftp()
        elif opcion == "5":
            bast_usuarios()
        elif opcion == "6":
            bast_contraseñas()
        elif opcion == "7":
            actualizar_sistema()
        elif opcion == "8":
            print("\nSaliendo del menú...")
            break
        else:
            error("Opción no válida")

    titulo("|=======================|\n|     BASTIONADO FINALIZADO    |\n|=======================|\n")

menu_bastionado()


