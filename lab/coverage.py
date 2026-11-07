"""Qué puede ver realmente esta combinación de herramientas en cada categoría.

Es una valoración del laboratorio, no de OWASP. Existe para que una categoría sin
hallazgos no se lea como una categoría sin problemas.
"""
COVERAGE = {
    "A01:2025": ("parcial", "Detecta rutas, redirecciones y exposición de datos. Los fallos de permisos entre usuarios exigen pruebas con sesiones reales."),
    "A02:2025": ("parcial", "Detecta cabeceras e infraestructura como código. No ve la configuración real del servidor en producción."),
    "A03:2025": ("parcial", "Trivy detecta dependencias vulnerables en lockfiles e imágenes, y Semgrep acciones de CI sin fijar. Sin lockfile no se ven dependencias, y nada comprueba la procedencia de los componentes."),
    "A04:2025": ("buena", "Algoritmos débiles, generadores aleatorios y texto en claro se detectan bien en código y en tráfico."),
    "A05:2025": ("buena", "Semgrep rastrea inyecciones en código y ZAP las ataca en modo activo. Sonar Community no hace análisis de flujo."),
    "A06:2025": ("escasa", "El diseño inseguro no se detecta con escáneres. Lo que aparece aquí son síntomas, como cabeceras ausentes."),
    "A07:2025": ("parcial", "Encuentra secretos por patrones conocidos y sesiones mal configuradas. Una contraseña sin formato reconocible puede pasar, y no se prueba el flujo de login."),
    "A08:2025": ("parcial", "Ve deserialización y acciones de CI sin fijar. No comprueba la integridad de los artefactos publicados."),
    "A09:2025": ("escasa", "Solo ve registros desactivados en infraestructura. Si la aplicación registra lo importante no se puede saber así."),
    "A10:2025": ("parcial", "Ve mensajes de error expuestos y algunos fallos de manejo de errores en el código."),
}
COVERAGE_LABELS = {"buena": "Buena", "parcial": "Parcial", "escasa": "Escasa"}
