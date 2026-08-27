if (!(Test-Path "venv\Scripts\python.exe")) { python -m venv venv }
& .\venv\Scripts\python.exe -m pip install -r requirements.txt
& .\venv\Scripts\python.exe scripts/train_model.py
& .\venv\Scripts\python.exe -m PyInstaller --clean --noconfirm --onefile --name NetScope --windowed --distpath exe --exclude-module torch --exclude-module torchvision --exclude-module tensorflow --exclude-module jupyter --exclude-module notebook --exclude-module cv2 --exclude-module moviepy --exclude-module bokeh --exclude-module dask --exclude-module distributed --exclude-module numba --add-data "models;models" --add-data "data;data" desktop_main.py
