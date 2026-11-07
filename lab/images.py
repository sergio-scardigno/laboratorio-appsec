"""Imágenes de los escáneres efímeros, fijadas por digest.

Las de los servicios fijos (SonarQube, Postgres, Juice Shop) están en compose.yaml.
"""

SEMGREP = (
    "semgrep/semgrep:1.179.0-nonroot"
    "@sha256:7d92d5b5515a6df82c645124629d989f697400d1b05aaac22805cbc09cb4b391"
)
SONAR_SCANNER = (
    "sonarsource/sonar-scanner-cli:12.3.1.4302_8.3.1"
    "@sha256:38207bba3d98c8ce6f6c051ea2b9f05a24480da78c9ee5945ceafc3d9de02b88"
)
# ZAP 2.17.0: el digest de ghcr.io/zaproxy/zaproxy:stable coincide con zap-stable:2.17.0.
ZAP = (
    "ghcr.io/zaproxy/zaproxy:stable"
    "@sha256:9624669db72f54d86c4b46a7064518bd9bf79d8c61a4c31befa9923489f328af"
)

# 0.76.1: posterior a todos los avisos de Trivy, incluido el compromiso de marzo de 2026
# (GHSA-69fq-xp46-6x23). El digest coincide en Docker Hub y en GHCR.
TRIVY = (
    "aquasec/trivy:0.76.1"
    "@sha256:790fd66d1697395d8693d1acaa1ea702406a20f109b6fc7bac8db623eca6c06c"
)

# Versión del código que clona el preset; debe coincidir con la imagen de compose.yaml.
JUICE_SHOP_REPO = "https://github.com/juice-shop/juice-shop.git"
JUICE_SHOP_TAG = "v20.3.0"
JUICE_SHOP_IMAGE = (
    "bkimminich/juice-shop:v20.3.0"
    "@sha256:cea5a4af4aacee498c491491af0408934ec81d004035c0a02ef3e54395e3bf27"
)
