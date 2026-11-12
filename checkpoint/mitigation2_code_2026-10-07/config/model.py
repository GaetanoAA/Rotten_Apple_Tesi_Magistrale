MODEL_CONFIG = {
    "model": "llama3.1:8b-instruct-q4_K_M",

    # Valore candidato per dry-run.
    # Consente una minima variabilità tra coppie,
    # mantenendo comunque il comportamento stabile.
    "temperature": 0.2,

    "top_p": 0.9,

    # Viene sovrascritto da experiment.py
    # con lo stesso valore nelle due condizioni
    # appartenenti alla stessa coppia.
    "seed": 42,

    "num_ctx": 8192,
    "num_predict": 512,
}