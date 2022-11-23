
# Rule Parser - MIPS

 Generador de alertas de seguridad bajo logs y alertas estipuladas. 


## Archivos

    1. DataLog.txt
        Este archivo contiene la información del log inicial.
    
    2. Parsing_Rules.config
        Este archivo continen los criterios de alertas sospechas para la comparación con el log.
    
    3. Alerts_Triggered.txt
        Una vez ejecutado el programa, este archivo contendrá las alertas tomadas

    4. Report.log
        Una vez ejecutado el programa, este archivo contendrá la información del log que cumple con los crierios de búsqueda del usuario


## Instalación y uso

Este programa está pensado para ser ejecutado bajo el simulador [MARS](http://courses.missouristate.edu/kenvollmar/mars/), por lo que su uso es requerido para el correcto funcionamiento de este programa.

Una vez cuente con este, puede clonar este repositorio con los archivos de prueba presentados.

```bash
  git clone https://github.com/NicolasMonta1807/Rule-Parser-Mips.git
  cd Rule-Parser-Mips
```

Dentro del simulador, puede abrir el código esencial del programa (logs.asm) para empezar a probarlo.

En caso de que desee testear sus propios archivos de configuración, debe cambiar los directorios encontrados en la siguiente sección:

[![Image from Gyazo](https://i.gyazo.com/334343845c8e865799f76f543639403c.png)](https://gyazo.com/334343845c8e865799f76f543639403c)
    

## Authors

- [@nicolasmonta1807](https://www.github.com/NicolasMonta1807)
- Gabriel Espitia Romero

