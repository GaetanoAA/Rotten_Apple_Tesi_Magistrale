from langchain_ollama import ChatOllama

from config.model import MODEL_CONFIG


def get_model() -> ChatOllama:
    return ChatOllama(
        model=MODEL_CONFIG["model"],
        temperature=MODEL_CONFIG["temperature"],
        top_p=MODEL_CONFIG["top_p"],
        seed=MODEL_CONFIG["seed"],
        num_ctx=MODEL_CONFIG["num_ctx"],
        num_predict=MODEL_CONFIG["num_predict"],
    )