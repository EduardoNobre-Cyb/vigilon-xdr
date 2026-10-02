from typing import Dict, List
import os
import logging
import shutil
from datetime import datetime, timezone
from data.models.models import get_session, Model


class ModelPromotionWorkflow:
    """Workflow to validate and deploy new models."""

    def __init__(self):
        """Initialize logger."""
        self.logger = logging.getLogger(__name__)

    def _get_db_session(self):
        """Get a fresh database session."""
        return get_session()

    def register_model(
        self,
        agent_id: str,
        metrics: Dict,
        model_path: str,
        model_type: str = None,
        config: Dict = None,
    ) -> Model:
        """Register newly trained model."""
        session = self._get_db_session()
        try:
            # Generate sequential version number based on existing models for this agent
            existing_count = session.query(Model).filter_by(agent_id=agent_id).count()
            version = f"{agent_id}_v{existing_count + 1}"

            model = Model(
                agent_id=agent_id,
                model_type=model_type or "unknown",
                version=version,
                accuracy=metrics["accuracy"],
                macro_f1=metrics["macro_f1"],
                recall_per_class=metrics.get("recall_per_class", {}),
                precision_per_class=metrics.get("precision_per_class", {}),
                model_path=model_path,
                training_date=datetime.now(timezone.utc),
                training_data_sources=metrics.get("data_sources", {}),
                training_duration_seconds=metrics.get("training_duration_seconds"),
                config=config or {},
            )
            session.add(model)
            session.commit()

            self.logger.info(f"Registered model {version}")
            return model
        finally:
            session.close()

    def approve_model(self, model_id: int, analyst_id: int, notes: str):
        """Analyst approves model for deployment."""
        session = self._get_db_session()
        try:
            model = session.query(Model).filter_by(id=model_id).first()
            if not model:
                self.logger.error(f"Model with id {model_id} not found")
                return

            model.is_approved = True
            model.approved_by = analyst_id
            session.commit()

            self.logger.info(f"Approved {model.version} by analyst {analyst_id}")
        finally:
            session.close()

    def deploy_model(self, model_id: int):
        """Activate model: copy from staging to production and hot-reload agent."""
        session = self._get_db_session()
        try:
            # First retrieve the model we're deploying
            model = session.query(Model).get(model_id)
            if not model:
                self.logger.error(f"Model with id {model_id} not found")
                return

            # Find and deactivate old model for this agent
            old_model = (
                session.query(Model)
                .filter_by(agent_id=model.agent_id, is_active=True)
                .first()
            )

            if old_model:
                old_model.is_active = False

            model.is_active = True
            session.commit()

            # Store these values before closing session (they're detached after session.close())
            model_id_local = model.id
            agent_id_local = model.agent_id
            model_path_local = model.model_path
            version_local = model.version
        finally:
            session.close()

        # 💾 DEPLOYMENT STEP: Copy trained model files from staging to production
        staging_path = (
            model_path_local  # e.g., data/models/threat_classifier_v2_staging
        )
        production_path = self._get_production_path(
            agent_id_local
        )  # e.g., data/models/threat_classifier_v2

        self.logger.info(f"📦 DEPLOYING MODEL: {staging_path} → {production_path}")
        success = self._deploy_model_files(staging_path, production_path)

        if not success:
            self.logger.error(f"❌ Failed to copy model files during deployment")
            return

        # Hot-reload model in agent with the PRODUCTION path
        try:
            from agents.agent_factory import get_agent

            agent = get_agent(agent_id_local)
            agent.load_model(production_path)
            self.logger.info(
                f"✅ Hot-reloaded agent {agent_id_local} from {production_path}"
            )
        except (ImportError, AttributeError) as e:
            self.logger.warning(f"⚠️ Could not hot-reload model: {e}")

        self.logger.info(f"✅ Deployed {version_local}")

    def _get_production_path(self, agent_id: str) -> str:
        """Get the production/deployment path for an agent."""
        production_paths = {
            "classifier": "data/models/threat_classifier_v2",
            "classifier_001": "data/models/threat_classifier_v2",
            "hunter": "data/models/threat_hunter",
            "hunter_001": "data/models/threat_hunter",
        }
        return production_paths.get(agent_id, f"data/models/{agent_id}")

    def _deploy_model_files(self, staging_path: str, production_path: str) -> bool:
        """Copy model files from staging to production, replacing old files."""
        try:
            # Ensure staging path exists
            if not os.path.exists(staging_path):
                self.logger.error(f"❌ Staging path does not exist: {staging_path}")
                return False

            # Create production directory if needed
            os.makedirs(production_path, exist_ok=True)

            # Copy all .pkl model files from staging to production
            model_files = [f for f in os.listdir(staging_path) if f.endswith(".pkl")]

            if not model_files:
                self.logger.error(f"❌ No .pkl model files found in {staging_path}")
                return False

            self.logger.info(
                f"📋 Copying {len(model_files)} model files to production..."
            )
            for model_file in model_files:
                source_file = os.path.join(staging_path, model_file)
                dest_file = os.path.join(production_path, model_file)
                shutil.copy2(source_file, dest_file)
                self.logger.info(f"   ✓ {model_file}")

            self.logger.info(f"✅ Successfully deployed {len(model_files)} model files")
            return True

        except Exception as e:
            self.logger.error(f"❌ Failed to deploy model files: {e}")
            return False

    def rollback_model(self, agent_id: str):
        """Rollback to previous model if current is broken."""
        session = self._get_db_session()
        try:
            current = (
                session.query(Model)
                .filter_by(agent_id=agent_id, is_active=True)
                .first()
            )

            previous = (
                session.query(Model)
                .filter_by(agent_id=agent_id)
                .order_by(Model.training_date.desc())
                .offset(1)
                .first()
            )

            if current and previous:
                current.is_active = False
                previous.is_active = True
                session.commit()

                # Store values before session close
                previous_model_path = previous.model_path
                previous_version = previous.version

                # Hot-reload previous model in agent (if get_agent is available)
                try:
                    from agents.agent_factory import get_agent

                    agent = get_agent(agent_id)
                    agent.load_model(previous_model_path)
                except (ImportError, AttributeError) as e:
                    self.logger.warning(f"Could not hot-reload model: {e}")

                self.logger.warning(f"Rolled back {agent_id} to {previous_version}")
            else:
                self.logger.warning(
                    f"Cannot rollback {agent_id}: no previous model available"
                )
        finally:
            session.close()
