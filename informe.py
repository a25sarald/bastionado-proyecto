from datetime import datetime  # importamos fecha y hora
import os     # para poder ejecutar comandos en el sistema operativo

archivo_logs = "/var/log/bastionado.log"    # ruta del archivo de logs
archivo_informe = "informe_bastionado.txt"  # nombre del informe generado con este script


def generar_informe():
    try:
        # comprobamos si existe el archivo de logs primero
        if not os.path.exists(archivo_logs):
            print("\033[91m[ERROR]\033[0m No existe el archivo de logs. Ejecuta primero el bastionado.")
            return
        # leemos el archivo:
        with open(archivo_logs, "r") as log:
            lineas = log.readlines()

        # creamos listas para organizar la informacion que obtengamos del log
        ok = []
        avisos = []
        riesgos = []
        recomendaciones = []
        errores = []

        # clasificacion de las lineas segun su etiqueta (lista)
        for linea in lineas:
            if "[OK]" in linea:
                ok.append(linea)
            elif "[AVISO]" in linea:
                avisos.append(linea)
            elif "[RIESGO]" in linea:
                riesgos.append(linea)
            elif "[RECOMENDACION]" in linea or "[RECOMENDACIÓN]" in linea:
                recomendaciones.append(linea)
            elif "[ERROR]" in linea:
                errores.append(linea)

        # creamos el informe
        with open(archivo_informe, "w") as informe:

            informe.write("\n==================================\n")
            informe.write("|   INFORME DE BASTIONADO DEL SISTEMA   |\n")
            informe.write("==================================\n\n")

            fecha = datetime.now().strftime("%d/%m/%Y %H:%M:%S")
            informe.write(f"Fecha de creación: {fecha}\n\n")

            # añadimos un resumen general
            informe.write("-----· RESUMEN ·-----\n")
            informe.write(f"OK: {len(ok)}\n")
            informe.write(f"Avisos: {len(avisos)}\n")
            informe.write(f"Riesgos: {len(riesgos)}\n")
            informe.write(f"Errores: {len(errores)}\n\n")

            # añadimos riesgos
            informe.write("-----· RIESGOS DETECTADOS ·-----\n")
            if riesgos:
                for r in riesgos:
                    informe.write(r)
            else:
                informe.write("No se detectaron riesgos\n")
            informe.write("\n")

            # añadimos avisos
            informe.write("-----· AVISOS ·-----\n")
            if avisos:
                for a in avisos:
                    informe.write(a)
            else:
                informe.write("No hay avisos\n")
            informe.write("\n")

            # añadimos las acciones realizadas (OK)
            informe.write("-----· ACCIONES REALIZADAS ·-----\n")
            if ok:
                for o in ok:
                    informe.write(o)
            else:
                informe.write("No se registraron acciones\n")
            informe.write("\n")

            # añadimos recomendaciones
            informe.write("-----· RECOMENDACIONES ·-----\n")
            if recomendaciones:
                for rec in recomendaciones:
                    informe.write(rec)
            else:
                informe.write("No hay recomendaciones\n")
            informe.write("\n")

            # añadimos errores
            informe.write("-----· ERRORES ·-----\n")
            if errores:
                for e in errores:
                    informe.write(e)
            else:
                informe.write("No se produjeron errores\n")
            informe.write("\n")

            informe.write("===================\n")
            informe.write("|      FIN DEL INFORME       |\n")
            informe.write("===================\n\n")

        print(f"\033[92m[OK]\033[0m Informe generado correctamente en: {archivo_informe}")

    except Exception as error_detectado:
        print(f"\033[91m[ERROR]\033[0m No se pudo generar el informe: {error_detectado}")

generar_informe()
