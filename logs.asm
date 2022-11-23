
	
					# //------------------------------------------ RULE PARSER ------------------------------------------\\ #
			
			
			
			
	# //------------------------------------------ VARIABLES INICIALES ------------------------------------------\\ #
			
.data
# Directorios
address: .asciiz "/home/nikoresu/Documents/PROJ3/datafixed.txt"
config: .asciiz "/home/nikoresu/Documents/PROJ3/Parsing_Rules.config"
alerts_trigger: .asciiz "/home/nikoresu/Documents/PROJ3/Alerts_Triggered.txt"
report_out: .asciiz "/home/nikoresu/Documents/PROJ3/Report.log"

# Lectura de archivos
buffer:  .space 3000
alerts: .space 500

# Tablas
ip_table: .space 700
usn_table: .space 410
tsp_table: .space 410

# Espacios para comparación
read_ip: .space 65
comp_ip: .space 65
read_user: .space 40
comp_user: .space 40

info_input: .space 60

# Escritura
trigger: .space 200
report: .space 40

# Mensajes
search_mess: .asciiz "1. BUSQUEDA POR IP\n2.BUSQUEDA POR USUARIO\nOpcion: "
error_mess: .asciiz "OPCION NO VALIDA\n\n"
ip_search: .asciiz "Digite la IP a buscar: "
usr_search: .asciiz "Digite el USUARIO a buscar: "
not_found: .asciiz "NO ENCONTRADO\n"
found: .asciiz "\nREPORTE GENERADO\n"


.text

	# ---------------------------- TABLA DE LOGS --------------------------- #
	
LOGS:
	# Abrir el archivo de logs
	li 	$v0,13
	la	$a0,address
	li	$a1,0
	li	$a2,0
	syscall
	
	move 	$t0, $v0
	
	# Leer archivo
	li	$v0,14
	move	$a0,$t0
	la	$a1,buffer
	li	$a2, 550
	syscall
	
	# Cerrar archivo
	li	$v0,16
	move	$t0,$a0
	syscall
	
	# Tratar de buscar la ip
	la $t0, buffer
	la $t2, ip_table
	la $t3, usn_table
	la $t4, tsp_table
	
	li $t5, 0
	


LOAD_LINE:
	# Inicia un contador para controlar la informacion que se está leyendo
	lb $t1, 0($t0)
	j SEARCH

SEARCH:
	# Lee hasta encontrar el final de linea
	beq $t1, 0, CONFIG
	# Busca el token
	beq $t1, ':', VALID
	# En caso de que no sea el token, sigue cargando
	addi $t0, $t0, 1
	lb $t1, 0($t0)
	j SEARCH
	
VALID:
	# Una vez encuentra el token, verifica el contador para ver de que se trata
	beq $t5, 0, IP
	beq $t5, 1, USN
	beq $t5, 2, TSP
	
IP:
	# Carga el primer numero de la IP
	addi $t5, $t5, 1
	addi $t0, $t0, 2
	lb $t1, 0($t0) 
	j NEXT_IP

NEXT_IP:
	# Lee hasta encontrar el token de separación 
	beq $t1, 39, SEPARATE_IP
	addi $t0, $t0, 1
	sb $t1, 0($t2) 
	addi $t2, $t2, 1
	lb $t1, 0($t0) 
	j NEXT_IP

SEPARATE_IP:
	# Digita un caracter como token para finalizar la tabla
	add $t2, $t2, 1
	li $t1, 95
	sb $t1, 0($t2)
	j LOAD_LINE
	
USN:
	# Carga la siguiente posición
	addi $t5, $t5, 1
	addi $t0, $t0, 2
	lb $t1, 0($t0) 
	j NEXT_USN

NEXT_USN:
	# Lee hasta encontrar el token de separación
	beq $t1, 39, SEPARATE_UN
	addi $t0, $t0, 1
	sb $t1, 0($t3) 
	addi $t3, $t3, 1
	lb $t1, 0($t0) 
	j NEXT_USN

SEPARATE_UN:
	# Digita un caracter como token para finalizar la tabla
	add $t3, $t3, 1
	li $t1, 95
	sb $t1, 0($t3)
	j LOAD_LINE
	
TSP:
	# Carga la siguiente posición
	li $t5, 0
	addi $t0, $t0, 2
	lb $t1, 0($t0) 
	j NEXT_TSP

NEXT_TSP:
	# Lee hasta encontrar el token de separación
	beq $t1, 39, SEPARATE_TP
	addi $t0, $t0, 1
	sb $t1, 0($t4) 
	addi $t4, $t4, 1
	lb $t1, 0($t0) 
	j NEXT_TSP

SEPARATE_TP:
	# Digita un caracter como token para finalizar la tabla
	add $t4, $t4, 1
	li $t1, 95
	j LOAD_LINE

NEXT_LINE:
	# Pasa a la siguiente linea de lectura
	addi $t0, $t0, 1
	j LOAD_LINE
	
	
	
	# ---------------------------- TABLA DE ALERTS --------------------------- #
	
	

CONFIG:
	# Abrir el archivo de configuraciones
	li 	$v0,13
	la	$a0,config
	li	$a1,0
	li	$a2,0
	syscall
	
	move 	$t0, $v0
	
	# Leer archivo
	li	$v0,14
	move	$a0,$t0
	la	$a1,alerts
	li	$a2, 124
	syscall
	
	# Cerrar archivo
	li	$v0,16
	move	$t0,$a0
	syscall

	la $s0, trigger
	la $t0, alerts
	la $t2, read_ip
	la $t4, ip_table
	la $t7, comp_ip 
	
	li $t3, 0	
	li $t6, 0
	li $t8, -1
	
	addi $t0, $t0, 3
	j LEER_IP
				
LEER_IP:
	# Carga cada IP de la tabla de alertas hasta encontrar la coma y/o un final de linea
	lb $t1, 0($t0)
	beq $t1, 10, USUARIOS
	beq $t1, 13, CARGAR_IP_COMPARAR
	beq $t1, ',', CARGAR_IP_COMPARAR
	sb $t1, 0($t2)
	addi $t0, $t0, 1
	addi $t2, $t2, 1
	addi $t3, $t3, 1
	j LEER_IP

CARGAR_IP_COMPARAR:
	# Carga cada IP de la tabla de logs para comparar con la IP leida de la tabla de alertas
	lb $t5, 0($t4)
	beq $t5, '_', RST_ALL
	beq $t5, 0, COMPARAR_IPS
	sb $t5, 0($t7)
	addi $t4, $t4, 1
	addi $t7, $t7, 1
	j CARGAR_IP_COMPARAR

RST_ALL:
	# En caso de llegar al final de la tabla, la IP de alerta no fue encontrada, por tanto, se reinician las variables de control
	li $t6, 0
	la $t4, ip_table
	la $t2, read_ip
	la $t7, comp_ip
	addi $t0 ,$t0, 1
	li $t3, 0
	li $t8, -1
	j LEER_IP
	
COMPARAR_IPS:
	# Inicializa las posiciones de los arreglos con la información a comparar
	addi $t8, $t8, 1
	la $t7, comp_ip
	la $t2, read_ip
	j COMPARAR_NUMEROS

COMPARAR_NUMEROS:
	# Compara bit a bit los numeros de las IP's. En caso de que la cantidad de bits leidos sean igual a la cantidad de bits comparados positivamente, la IP fue encontrada
	lb $t1, 0($t2)
	lb $t5, 0($t7)
	beq $t3, $t6, IGUALES
	bne $t1, $t5, RST_ANTES_CARGAR
	addi $t6, $t6, 1
	addi $t2, $t2, 1
	addi $t7, $t7, 1
	j COMPARAR_NUMEROS

RST_ANTES_CARGAR:
	# Si la IP no corresponde, se reinician las variables de control antes de comparar con la siguiente
	addi $t4, $t4, 1
	la $t7, comp_ip
	li $t6, 0	
	j CARGAR_IP_COMPARAR

IGUALES:
	# Una vez se encuentre la IP, se reinician las variables de control y se procede a cargar la información a la tabla de TRIGGERS
	addi $t0, $t0, 1
	la $t2, read_ip
	la $t4, ip_table
	la $t7, comp_ip
	li $t3, 0
	li $t6, 0
	j BUSCAR_IP
	
	# ---------------------------- TABLA DE TRIGGERS PARA IP's--------------------------- #

BUSCAR_IP:
	# Carga la dirección de la tabla de IP's del log
	la $s1, ip_table
	li $s3, 0
	j IP_LOOP

IP_LOOP:
	# Usando el contador de posiciones tomado del paso anterior, compara la posición de la IP leida
	lb $s2, 0($s1)
	beq $s2, 0, COMP_IP_POS
	addi $s1, $s1, 1
	j IP_LOOP

COMP_IP_POS:
	# Verifica si la posición es la correspondiente
	addi $s3, $s3, 1
	addi $s1, $s1, 1
	beq $s3, $t8, IP_FOUND
	j IP_LOOP

IP_FOUND:
	# Una vez es encontrada, se escribe a la tabla
	lb $s2, 0($s1)
	beq $s2, 0, BUSCAR_USR
	sb $s2, 0($s0)
	addi $s1, $s1, 1
	addi $s0, $s0, 1
	j IP_FOUND
		
	# //---------------------------- FUNCIÓN "RECURSIVA" PARA USUARIOS Y TIMESTAMPS ---------------------------\\ #

BUSCAR_USR:
	li $s5, '-'
	sb $s5, 0($s0)
	addi $s0, $s0, 1
	la $s1, usn_table
	li $s3, 0
	j CORR_LOOP
	
CORR_LOOP:
	lb $s2, 0($s1)
	beq $s2, 0, COMP_POS
	addi $s1, $s1, 1
	j CORR_LOOP

COMP_POS:
	addi $s3, $s3, 1
	addi $s1, $s1, 1
	beq $s3, $t8, USR_FOUND
	j CORR_LOOP

USR_FOUND:
	lb $s2, 0($s1)
	beq $s2, 0, BUSCAR_TSP
	sb $s2, 0($s0)
	addi $s1, $s1, 1
	addi $s0, $s0, 1
	j USR_FOUND
	
BUSCAR_TSP:
	li $s5, '-'
	sb $s5, 0($s0)
	addi $s0, $s0, 1
	la $s1, tsp_table
	li $s3, 0
	j TSP_LOOP
	
TSP_LOOP:
	lb $s2, 0($s1)
	beq $s2, 0, COMP_TSP_POS
	addi $s1, $s1, 1
	j TSP_LOOP

COMP_TSP_POS:
	addi $s3, $s3, 1
	addi $s1, $s1, 1
	beq $s3, $t8, TSP_FOUND
	j TSP_LOOP

TSP_FOUND:
	lb $s2, 0($s1)
	beq $s2, 0, CONTINUE
	sb $s2, 0($s0)
	addi $s1, $s1, 1
	addi $s0, $s0, 1
	j  TSP_FOUND

CONTINUE:
	li $s6, '\r'
	sb $s6, 0($s0)
	addi $s0, $s0, 1
	li $s6, '\n'
	sb $s6, 0($s0)
	addi $s0, $s0, 1
	li $t8, -1
	j LEER_IP
	
	# //------------------------------------------------------------------------------------\\ #
	
	# ---------------------------- TABLA DE TRIGGERS PARA USUARIOS --------------------------- #

USUARIOS:
	# Inicializa las variables de control
	la $t2, read_user
	la $t4, usn_table
	la $t7, comp_user
	
	li $t3, 0
	li $t6, 0
	li $t8, -1
	j INIT_USUARIOS
	

INIT_USUARIOS:
	# Recorre la tabla de alerts hasta encontrar la posición correspondiente a la información de usuarios
	beq $t1, ':', PRIMER_USUARIO
	addi $t0, $t0, 1
	lb $t1, 0($t0)
	j INIT_USUARIOS
	
PRIMER_USUARIO:
	addi $t0, $t0, 1
	j LEER_USUARIO

LEER_USUARIO:
	# Carga el usuario de la alerta hasta encontrar una coma y/o final de linea
	lb $t1, 0($t0)
	beq $t1, 10, CARGAR_TRIGGER
	beq $t1, 13, CARGAR_USUARIO_COMPARAR
	beq $t1, ',', CARGAR_USUARIO_COMPARAR
	sb $t1, 0($t2)
	addi $t0, $t0, 1
	addi $t2, $t2, 1
	addi $t3, $t3, 1
	j LEER_USUARIO

CARGAR_USUARIO_COMPARAR:
	# Carga los usuarios de la tabla de logs para comparar
	lb $t5, 0($t4)
	beq $t5, '_', RST_ALL_USR
	beq $t5, 0, COMPARAR_USUARIO
	sb $t5, 0($t7)
	addi $t7, $t7, 1
	addi $t4, $t4, 1
 	j CARGAR_USUARIO_COMPARAR

RST_ALL_USR:
	# En caso de llegar al final de la tabla, el usuario no fue encontrado y reinicia las variables de control
	li $t6, 0
	la $t2, read_user
	la $t4, usn_table
	la $t7, comp_user
	addi $t0, $t0, 1
	li $t3, 0
	li $t8, -1
	j LEER_USUARIO

COMPARAR_USUARIO:
	# Inicializa las posiciones de los arreglos a comparar
	addi $t8, $t8, 1
	la $t7, comp_user
	la $t2, read_user
	j COMPARAR_LETRAS
	
COMPARAR_LETRAS:
	# Compara bit a bit los caracteres de los arreglos, en caso de que el contador de caracteres iguales sea igual a la cantidad de caracteres del usuario, este fue encontrado
	lb $t1, 0($t2)
	lb $t5, 0($t7)
	beq $t3, $t6, IGUAL_USUARIO
	bne $t1, $t5, RST_ANTES_USUARIO
	addi $t6, $t6, 1
	addi $t2, $t2, 1
	addi $t7, $t7, 1
	j COMPARAR_LETRAS
	
RST_ANTES_USUARIO:
	# En caso de que el usuario a comparar no corresponda, reinicia las variables de control
	addi $t4, $t4, 1
	la $t7, comp_user
	li $t6, 0
	j CARGAR_USUARIO_COMPARAR

IGUAL_USUARIO:
	# En caso de encontrar el usuario, se carga su información a la tabla de triggers
	addi $t0, $t0, 1
	la $t2, read_user
	la $t4, usn_table
	la $t7, comp_user
	li $t3, 0
	li $t6, 0
	j BUSCAR_IP_USR
	
	# //---------------------------- FUNCIÓN DE BÚSQUEDA DE INFORMACIÓN DE LA ALERTA GENERADA (IGUAL QUE LA ANTERIOR) ---------------------------\\ #

BUSCAR_IP_USR:
	la $s1, ip_table
	li $s3, 0
	j IP_LOOP_USR

IP_LOOP_USR:
	lb $s2, 0($s1)
	beq $s2, 0, COMP_IP_POS_USR
	addi $s1, $s1, 1
	j IP_LOOP_USR

COMP_IP_POS_USR:
	addi $s3, $s3, 1
	addi $s1, $s1, 1
	beq $s3, $t8, IP_FOUND_USER
	j IP_LOOP_USR

IP_FOUND_USER:
	lb $s2, 0($s1)
	beq $s2, 0, BUSCAR_USR_SEC
	sb $s2, 0($s0)
	addi $s1, $s1, 1
	addi $s0, $s0, 1
	j IP_FOUND_USER

BUSCAR_USR_SEC:
	li $s5, '-'
	sb $s5, 0($s0)
	addi $s0, $s0, 1
	la $s1, usn_table
	li $s3, 0
	j USR_LOOP

USR_LOOP:
	lb $s2, 0($s1)
	beq $s2, 0, COMP_USR_POS
	addi $s1, $s1, 1
	j USR_LOOP

COMP_USR_POS:
	addi $s3, $s3, 1
	addi $s1, $s1, 1
	beq $s3, $t8, USR_FOUND_SEC
	j USR_LOOP

USR_FOUND_SEC:
	lb $s2, 0($s1)
	beq $s2, 0, BUSCAR_TSP_SEC
	sb $s2, 0($s0)
	addi $s1, $s1, 1
	addi $s0, $s0, 1
	j USR_FOUND_SEC

BUSCAR_TSP_SEC:
	li $s5, '-'
	sb $s5, 0($s0)
	addi $s0, $s0, 1
	la $s1, tsp_table
	li $s3, 0
	j TSP_LOOP_SEC

TSP_LOOP_SEC:
	lb $s2, 0($s1)
	beq $s2, 0, TSP_POS
	addi $s1, $s1, 1
	j TSP_LOOP_SEC

TSP_POS:
	addi $s3, $s3, 1
	addi $s1, $s1, 1
	beq $s3, $t8, TSP_FOUND_SEC
	j TSP_LOOP_SEC
	
TSP_FOUND_SEC:
	lb $s2, 0($s1)
	beq $s2, 0, CONTINUE_SEC
	sb $s2, 0($s0)
	addi $s1, $s1, 1
	addi $s0, $s0, 1
	j  TSP_FOUND_SEC
	
CONTINUE_SEC:
	li $s6, '\r'
	sb $s6, 0($s0)
	addi $s0, $s0, 1
	li $s6, '\n'
	sb $s6, 0($s0)
	addi $s0, $s0, 1
	li $t8, -1
	j LEER_USUARIO

	# //-------------------------------------------------------------------------------------------------------------------------\\ #
	
	# //------------------------------------------ ARCHIVAR LA INFORMACIÓN DE TRIGGERS ------------------------------------------\\ #

CARGAR_TRIGGER:
	li $v0, 13
	la $a0, alerts_trigger
	la $a1, 1
	la $a2, 0
	syscall
	
	move $k0, $v0
	
	li $v0, 15
	move $a0, $k0
	la $a1, trigger
	la $a2, 175
	syscall
	
	li $v0, 16
	move $a0, $k0
	syscall
	
	j BUSQUEDA

	# //------------------------------------------ BÚSQUEDA DE LOG POR ENTRADA EN CONSOLA ------------------------------------------\\ #

BUSQUEDA:
	# Muestra un menu para la selección del criterio de búsqueda
	li $v0, 4
	la $a0, search_mess
	syscall
	
	li $v0, 5
	syscall
	
	move $t1, $v0
	
	beq $t1, 1, IP_SEARCH
	beq $t1, 2, USR_SEARCH
	j ERROR

	# //------------------------------------------ BÚSQUEDA POR IP ------------------------------------------\\ #

IP_SEARCH:
	# Solicita la IP a buscar
	li $v0, 4
	la $a0, ip_search
	syscall

	li $v0, 8
	la $a0, info_input
	li $a1, 15
	syscall
			
	la $t0, info_input
	li $t3, 0		
			
	j COUNT_CHARS

COUNT_CHARS:
	# Cuenta los caracteres de la IP ingresada
	lb $t1, 0($t0)
	beq $t1, 10, GO_SEARCH_IP
	beq $t1, 0, GO_SEARCH_IP
	addi $t0, $t0, 1
	addi $t3, $t3, 1
	j COUNT_CHARS

GO_SEARCH_IP:
	# Inicializa las variables para la comparación
	la $t4, ip_table
	la $t2, info_input
	la $t7, comp_ip
	
	li $t6, 0
	li $t8, -1
	
	j LOAD_IP_TABLE

LOAD_IP_TABLE:
	# Busca la información necesaria en la tabla de IP's del log - En caso de llegar al final de la tabla, esta no fue encontrada
	lb $t5, 0($t4)
	beq $t5, '_', NOT_FOUND
	beq $t5, 0, COMPARE
	sb $t5, 0($t7)
	addi $t4, $t4, 1
	addi $t7, $t7, 1
	j LOAD_IP_TABLE

COMPARE:
	# Inicializa las posiciones de los arreglos para la comparación
	addi $t8, $t8, 1
	la $t7, comp_ip
	la $t2, info_input
	j COMPARE_BITWISE
	
COMPARE_BITWISE:
	# Compara bit a bit los caracteres de la IP. En caso de corresponder la cantidad de caracteres iguales con la cantidad de caracteres de la IP, esta fue encontrada
	lb $t1, 0($t2)
	lb $t5, 0($t7)
	beq $t3, $t6, INFO_FOUND
	bne $t1, $t5, RESET_NEXT
	addi $t6, $t6, 1
	addi $t2, $t2, 1
	addi $t7, $t7, 1
	j COMPARE_BITWISE

RESET_NEXT:
	# En caso de no corresponder, reinicia las variables de control para la proxima comparación
	addi $t4, $t4, 1
	la $t7, comp_ip
	li $t6, 0	
	j LOAD_IP_TABLE

INFO_FOUND:
	# Si la información fue encontrada, genera el reporte
	li $v0, 4
	la $a0, found
	syscall

	la $s0, report
	la $s1, ip_table
	li $s3, 0
	j IP_LOOP_REP


	# //---------------------------- FUNCIÓN DE BÚSQUEDA DE INFORMACIÓN DE LA ALERTA GENERADA (IGUAL QUE LA ANTERIOR) ---------------------------\\ #
	

IP_LOOP_REP:
	lb $s2, 0($s1)
	beq $s2, 0, COMP_IP_POS_REP
	addi $s1, $s1, 1
	j IP_LOOP_REP

COMP_IP_POS_REP:
	addi $s3, $s3, 1
	addi $s1, $s1, 1
	beq $s3, $t8, IP_FOUND_REP
	j IP_LOOP_REP

IP_FOUND_REP:
	lb $s2, 0($s1)
	beq $s2, 0, BUSCAR_USR_REP
	sb $s2, 0($s0)
	addi $s1, $s1, 1
	addi $s0, $s0, 1
	j IP_FOUND_REP

BUSCAR_USR_REP:
	li $s5, '-'
	sb $s5, 0($s0)
	addi $s0, $s0, 1
	la $s1, usn_table
	li $s3, 0
	j CORR_LOOP_REP
	
CORR_LOOP_REP:
	lb $s2, 0($s1)
	beq $s2, 0, COMP_POS_REP
	addi $s1, $s1, 1
	j CORR_LOOP_REP

COMP_POS_REP:
	addi $s3, $s3, 1
	addi $s1, $s1, 1
	beq $s3, $t8, USR_FOUND_REP
	j CORR_LOOP_REP

USR_FOUND_REP:
	lb $s2, 0($s1)
	beq $s2, 0, BUSCAR_TSP_REP
	sb $s2, 0($s0)
	addi $s1, $s1, 1
	addi $s0, $s0, 1
	j USR_FOUND_REP

BUSCAR_TSP_REP:
	li $s5, '-'
	sb $s5, 0($s0)
	addi $s0, $s0, 1
	la $s1, tsp_table
	li $s3, 0
	j TSP_LOOP_REP
	
TSP_LOOP_REP:
	lb $s2, 0($s1)
	beq $s2, 0, COMP_TSP_POS_REP
	addi $s1, $s1, 1
	j TSP_LOOP_REP

COMP_TSP_POS_REP:
	addi $s3, $s3, 1
	addi $s1, $s1, 1
	beq $s3, $t8, TSP_FOUND_REP
	j TSP_LOOP_REP

TSP_FOUND_REP:
	lb $s2, 0($s1)
	beq $s2, 0, CONTINUE_REP
	sb $s2, 0($s0)
	addi $s1, $s1, 1
	addi $s0, $s0, 1
	j  TSP_FOUND_REP

CONTINUE_REP:
	li $s6, '\r'
	sb $s6, 0($s0)
	addi $s0, $s0, 1
	li $s6, '\n'
	sb $s6, 0($s0)
	addi $s0, $s0, 1
	li $t8, -1
	j CARGAR_REP

	# //-------------------------------------------------------------------------------------------------------------------------\\ #
	
	# //------------------------------------------------- ARCHIVAR EL REPORTE ---------------------------------------------------\\ #

CARGAR_REP:
	li $v0, 13
	la $a0, report_out
	la $a1, 1
	la $a2, 0
	syscall
	
	move $k0, $v0
	
	li $v0, 15
	move $a0, $k0
	la $a1, report
	la $a2, 40
	syscall
	
	li $v0, 16
	move $a0, $k0
	syscall
	
	j EXIT
	
	# //------------------------------------------------------ INFORMACIÓN NO ENCONTRADA--------------------------------------------------------------\\ #

NOT_FOUND:
	# Muestra por consola el mensaje correspondiente
	li $v0, 4
	la $a0, not_found
	syscall
	j EXIT
	
		
	# //------------------------------------------ BÚSQUEDA POR USUARIO (MANTIENE LOS CRITERIOS DE LA BÚSQUEDA POR IP) ------------------------------------------\\ #
	

USR_SEARCH:
	li $v0, 4
	la $a0, usr_search
	syscall

	li $v0, 8
	la $a0, info_input
	li $a1, 15
	syscall
			
	la $t0, info_input
	li $t3, 0		
			
	j COUNT_CHARS_USR

COUNT_CHARS_USR:
	lb $t1, 0($t0)
	beq $t1, 10, GO_SEARCH_IP_USR
	beq $t1, 0, GO_SEARCH_IP_USR
	addi $t0, $t0, 1
	addi $t3, $t3, 1
	j COUNT_CHARS_USR

GO_SEARCH_IP_USR:
	la $t4, usn_table
	la $t2, info_input
	la $t7, comp_user
	
	li $t6, 0
	li $t8, -1
	
	j LOAD_USR_TABLE

LOAD_USR_TABLE:
	lb $t5, 0($t4)
	beq $t5, '_', NOT_FOUND
	beq $t5, 0, COMPARE_USR
	sb $t5, 0($t7)
	addi $t4, $t4, 1
	addi $t7, $t7, 1
	j LOAD_USR_TABLE

COMPARE_USR:
	addi $t8, $t8, 1
	la $t7, comp_user
	la $t2, info_input
	j COMPARE_BITWISE_USR
	
COMPARE_BITWISE_USR:
	lb $t1, 0($t2)
	lb $t5, 0($t7)
	beq $t3, $t6, INFO_FOUND_USR
	bne $t1, $t5, RESET_NEXT_USR
	addi $t6, $t6, 1
	addi $t2, $t2, 1
	addi $t7, $t7, 1
	j COMPARE_BITWISE_USR

RESET_NEXT_USR:
	addi $t4, $t4, 1
	la $t7, comp_user
	li $t6, 0	
	j LOAD_USR_TABLE

INFO_FOUND_USR:
	li $v0, 4
	la $a0, found
	syscall

	la $s0, report
	la $s1, ip_table
	li $s3, 0
	j IP_LOOP_REP_USR

IP_LOOP_REP_USR:
	lb $s2, 0($s1)
	beq $s2, 0, COMP_IP_POS_REP_USR
	addi $s1, $s1, 1
	j IP_LOOP_REP_USR

COMP_IP_POS_REP_USR:
	addi $s3, $s3, 1
	addi $s1, $s1, 1
	beq $s3, $t8, IP_FOUND_REP_USR
	j IP_LOOP_REP_USR

IP_FOUND_REP_USR:
	lb $s2, 0($s1)
	beq $s2, 0, BUSCAR_USR_REP_USR
	sb $s2, 0($s0)
	addi $s1, $s1, 1
	addi $s0, $s0, 1
	j IP_FOUND_REP_USR

BUSCAR_USR_REP_USR:
	li $s5, '-'
	sb $s5, 0($s0)
	addi $s0, $s0, 1
	la $s1, usn_table
	li $s3, 0
	j CORR_LOOP_REP_USR
	
CORR_LOOP_REP_USR:
	lb $s2, 0($s1)
	beq $s2, 0, COMP_POS_REP_USR
	addi $s1, $s1, 1
	j CORR_LOOP_REP_USR

COMP_POS_REP_USR:
	addi $s3, $s3, 1
	addi $s1, $s1, 1
	beq $s3, $t8, USR_FOUND_REP_USR
	j CORR_LOOP_REP_USR

USR_FOUND_REP_USR:
	lb $s2, 0($s1)
	beq $s2, 0, BUSCAR_TSP_REP_USR
	sb $s2, 0($s0)
	addi $s1, $s1, 1
	addi $s0, $s0, 1
	j USR_FOUND_REP_USR

BUSCAR_TSP_REP_USR:
	li $s5, '-'
	sb $s5, 0($s0)
	addi $s0, $s0, 1
	la $s1, tsp_table
	li $s3, 0
	j TSP_LOOP_REP_USR
	
TSP_LOOP_REP_USR:
	lb $s2, 0($s1)
	beq $s2, 0, COMP_TSP_POS_REP_USR
	addi $s1, $s1, 1
	j TSP_LOOP_REP_USR

COMP_TSP_POS_REP_USR:
	addi $s3, $s3, 1
	addi $s1, $s1, 1
	beq $s3, $t8, TSP_FOUND_REP_USR
	j TSP_LOOP_REP_USR

TSP_FOUND_REP_USR:
	lb $s2, 0($s1)
	beq $s2, 0, CONTINUE_REP_USR
	sb $s2, 0($s0)
	addi $s1, $s1, 1
	addi $s0, $s0, 1
	j  TSP_FOUND_REP_USR

CONTINUE_REP_USR:
	li $s6, '\r'
	sb $s6, 0($s0)
	addi $s0, $s0, 1
	li $s6, '\n'
	sb $s6, 0($s0)
	addi $s0, $s0, 1
	li $t8, -1
	j CARGAR_REP

	# //------------------------------------------ ERROR ------------------------------------------\\ #

ERROR:
	# Muestra un mensaje por consola si la opción seleccionada no se encuentra en el menú
	li $v0, 4
	la $a0, error_mess
	syscall
	j BUSQUEDA
	

EXIT:
	# Finaliza el programa
	li $v0, 10
	syscall