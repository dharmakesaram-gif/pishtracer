import os
import torch
import torch.nn as nn
import torch.optim as optim
import numpy as np
from typing import Dict, Any, Tuple

# -------------------------------------------------------------
# PhishNet: Deep Neural Network for Email Phishing Detection
# Architecture: Dual-Branch Dense Feature + Token Embedding Net
# -------------------------------------------------------------

class PhishNet(nn.Module):
    """
    PyTorch Deep Neural Network combining structured forensic metadata
    with semantic token representations for email threat classification.
    """
    def __init__(self, tabular_dim: int = 15, vocab_size: int = 500, embed_dim: int = 16):
        super(PhishNet, self).__init__()
        
        # Branch 1: Tabular & Heuristic Feature Dense Net
        self.tabular_net = nn.Sequential(
            nn.Linear(tabular_dim, 64),
            nn.BatchNorm1d(64),
            nn.LeakyReLU(0.2),
            nn.Dropout(0.25),
            nn.Linear(64, 32),
            nn.BatchNorm1d(32),
            nn.LeakyReLU(0.2),
            nn.Linear(32, 16)
        )
        
        # Branch 2: Semantic Token Embedding Bag (NLP Text Branch)
        self.embedding = nn.EmbeddingBag(vocab_size, embed_dim, mode='mean')
        self.text_fc = nn.Sequential(
            nn.Linear(embed_dim, 16),
            nn.LeakyReLU(0.2)
        )
        
        # Branch 3: Deep Fusion & Classification Head
        self.fusion_head = nn.Sequential(
            nn.Linear(16 + 16, 32),
            nn.BatchNorm1d(32),
            nn.LeakyReLU(0.2),
            nn.Dropout(0.2),
            nn.Linear(32, 16),
            nn.LeakyReLU(0.2),
            nn.Linear(16, 1),
            nn.Sigmoid()
        )

    def forward(self, tabular_x: torch.Tensor, text_tokens: torch.Tensor, offsets: torch.Tensor = None) -> torch.Tensor:
        # Pass structured metrics
        tab_out = self.tabular_net(tabular_x)
        
        # Pass NLP tokens
        text_emb = self.embedding(text_tokens, offsets)
        text_out = self.text_fc(text_emb)
        
        # Concatenate & pass through fusion classifier head
        combined = torch.cat([tab_out, text_out], dim=1)
        prob = self.fusion_head(combined)
        return prob


class PhishNetManager:
    """Manages training, persistence, and inference for the PyTorch Neural Network."""
    MODEL_WEIGHTS_PATH = os.path.join(os.path.dirname(__file__), 'phishnet_weights.pt')

    def __init__(self):
        self.model = PhishNet(tabular_dim=15, vocab_size=500, embed_dim=16)
        self.model.eval()
        self._load_weights_if_available()

    def _load_weights_if_available(self):
        if os.path.exists(self.MODEL_WEIGHTS_PATH):
            try:
                state_dict = torch.load(self.MODEL_WEIGHTS_PATH, map_location=torch.device('cpu'))
                self.model.load_state_dict(state_dict)
                self.model.eval()
            except Exception as e:
                print(f"[PhishNet] Could not load weights: {e}")

    def text_to_token_ids(self, text: str, max_vocab: int = 500) -> torch.Tensor:
        """Lightweight token hashing into vocabulary buckets."""
        words = text.lower().split()
        if not words:
            return torch.tensor([0], dtype=torch.long)
        token_ids = [abs(hash(w)) % (max_vocab - 1) + 1 for w in words[:100]]
        return torch.tensor(token_ids, dtype=torch.long)

    def predict(self, feature_vector: list, email_text: str = "") -> Dict[str, Any]:
        """Run forward pass inference through the Deep Neural Network."""
        self.model.eval()
        with torch.no_grad():
            tab_tensor = torch.tensor([feature_vector], dtype=torch.float32)
            token_tensor = self.text_to_token_ids(email_text)
            offsets = torch.tensor([0], dtype=torch.long)
            
            prob = self.model(tab_tensor, token_tensor, offsets).item()

        risk_level = "CRITICAL" if prob >= 0.8 else ("HIGH" if prob >= 0.6 else ("MEDIUM" if prob >= 0.3 else "LOW"))

        return {
            "neural_network_probability": round(prob, 4),
            "neural_risk_level": risk_level,
            "architecture": "PyTorch Dual-Branch Deep Neural Network (PhishNet)",
            "layers": [
                "Tabular Branch: Linear(15->64) -> BatchNorm -> LeakyReLU -> Dropout(0.25) -> Linear(64->16)",
                "NLP Token Branch: EmbeddingBag(500, 16) -> Linear(16->16)",
                "Fusion Head: Linear(32->32) -> BatchNorm -> Dropout(0.2) -> Linear(32->1) -> Sigmoid"
            ],
            "framework": f"PyTorch {torch.__version__}"
        }

    def train_demo_network(self, epochs: int = 25) -> Dict[str, Any]:
        """Train PhishNet on synthetic threat telemetry and save model weights."""
        print(f"[PhishNet] Training PyTorch Deep Neural Network for {epochs} epochs...")
        
        # Generate synthetic training pairs (Phishing vs Legitimate)
        np.random.seed(42)
        n_samples = 400
        
        # Class 0: Legitimate (lower scores)
        X_legit = np.random.uniform(0.0, 1.0, (n_samples // 2, 15))
        y_legit = np.zeros((n_samples // 2, 1))
        
        # Class 1: Phishing (higher features for urgency, financial terms, mismatches)
        X_phish = np.random.uniform(0.5, 3.5, (n_samples // 2, 15))
        y_phish = np.ones((n_samples // 2, 1))
        
        X_data = np.vstack([X_legit, X_phish])
        y_data = np.vstack([y_legit, y_phish])
        
        # Shuffle
        indices = np.arange(n_samples)
        np.random.shuffle(indices)
        X_data = torch.tensor(X_data[indices], dtype=torch.float32)
        y_data = torch.tensor(y_data[indices], dtype=torch.float32)

        # Synthetic token bags
        all_tokens = torch.randint(1, 499, (n_samples * 20,), dtype=torch.long)
        offsets = torch.arange(0, n_samples * 20, 20, dtype=torch.long)

        # Training setup
        self.model.train()
        criterion = nn.BCELoss()
        optimizer = optim.Adam(self.model.parameters(), lr=0.005, weight_decay=1e-4)

        final_loss = 0.0
        for epoch in range(epochs):
            optimizer.zero_grad()
            outputs = self.model(X_data, all_tokens, offsets)
            loss = criterion(outputs, y_data)
            loss.backward()
            optimizer.step()
            final_loss = loss.item()

        # Save weights
        torch.save(self.model.state_dict(), self.MODEL_WEIGHTS_PATH)
        self.model.eval()
        print(f"[PhishNet] Training complete! Final BCELoss: {final_loss:.4f}. Saved to {self.MODEL_WEIGHTS_PATH}")

        return {
            "status": "success",
            "epochs": epochs,
            "final_bce_loss": round(final_loss, 4),
            "weights_path": self.MODEL_WEIGHTS_PATH
        }
