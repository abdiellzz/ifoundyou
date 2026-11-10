# I Found You — Forensic Metadata Analysis Tool

Herramienta web de análisis forense de archivos. Todo el análisis se hace **localmente en el navegador**: los archivos no se suben a ningún servidor.

## Funciones

- **Metadatos:** EXIF e información interna de imágenes y documentos.
- **Forense:** detección de firmas de archivo, gráfico de entropía, visor hexadecimal y explorador de strings.
- **Búsqueda de ocultos:** contenido embebido o disfrazado dentro de archivos.
- **Laboratorio de imagen:** herramientas de esteganografía.
- **Reporte:** resumen del análisis de cada archivo.
- **Demo y modo CTF / Esteganografía:** archivos de ejemplo y retos para practicar.

Admite varios archivos a la vez, de hasta 150 MB cada uno.

## Requisitos

- Node.js 18 o superior
- npm

## Instalación y uso

```bash
git clone https://github.com/abdiellzz/ifoundyou
cd ifoundyou
npm install
npm run dev
```

Abre la dirección que muestre Vite (normalmente `http://localhost:5173`), arrastra uno o varios archivos o haz clic para elegirlos, y selecciona cada uno en la barra lateral para ver sus secciones.

### Build

```bash
npm run build
npm run preview
```

El proyecto usa `vite-plugin-singlefile`, por lo que el build en `dist/` se genera como un único HTML.

## Stack

React 19, TypeScript, Vite, Tailwind CSS 4, [exifr](https://github.com/MikeKovarik/exifr), JSZip, spark-md5 y lucide-react.

## Estructura

```
src/
  components/   Vistas de la interfaz (metadatos, forense, hex, imagen, reporte, CTF)
  lib/          Lógica de análisis (firmas, entropía, esteganografía, limpieza, reportes)
```

## Uso responsable

Úsala solo con archivos propios o con autorización, para análisis forense, aprendizaje y CTFs.
