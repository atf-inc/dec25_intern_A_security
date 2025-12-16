# DistilBERT Fine-Tuning Technique

**Current Technique: Full Fine-Tuning (Transfer Learning)**

We are currently applying **Full Fine-Tuning** on the pre-trained `DistilBertForSequenceClassification` model.

**Justification:**
*   **Domain Shift**: SQL queries differ significantly from the natural language text (Wikipedia/Books) the model was originally pre-trained on. Full fine-tuning allows the model to adjust all its weights to understand SQL syntax and injection patterns effectively.
*   **Performance**: For security-critical applications, maximizing accuracy is paramount. Full fine-tuning typically yields better performance than parameter-efficient methods (like LoRA) when the domain shift is large.
*   **Simplicity**: The current deployment size of DistilBERT (~260MB) is manageable, so we do not currently require the storage savings of adapters.
