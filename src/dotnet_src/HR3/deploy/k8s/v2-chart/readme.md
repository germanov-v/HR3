# 1) Подготовь values с адресами образов
helm upgrade --install jr2 ./jr2 -n jr2 --create-namespace

# Проверка
kubectl -n jr2 get pods,svc,ingress,certificate,certificateRequest,order,challenge
