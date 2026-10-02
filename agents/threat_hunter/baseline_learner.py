import json
from datetime import datetime, timezone, timedelta
from typing import Dict, Tuple
from statistics import mean, stdev
from collections import defaultdict

from sqlalchemy import func, and_
from data.models.models import get_session, LogEvent, Asset, AssetBehaviorBaseline


class BaseLineLearner:
    """Learn normal behavior from historical clean logs."""

    # Only use logs older than 2 days to avoid contamination from attacks
    LEARNING_WINDOW_DAYS = 7
    MIN_HISTORY_DAYS = 2

    def learn_baselines_for_all_assets(self):
        """Learn baselines for all assets in the system."""

        session = get_session()
        try:
            assets = session.query(Asset).all()

            print(f"🔍 Learning baselines for {len(assets)} assets...")
            updated_count = 0

            for asset in assets:
                if self.learn_baseline(asset):
                    updated_count += 1

            print(f"✅ Updated baselines for {updated_count} assets.")
            return updated_count

        finally:
            session.close()

    def learn_baseline(self, asset: Asset) -> bool:
        """Learn baseline for a single asset."""

        session = get_session()
        try:
            asset_id = asset.id
            now = datetime.now(timezone.utc)

            # Collect logs from last 7 days
            lookback_start = now - timedelta(days=self.LEARNING_HISTORY_DAYS)
            lookback_end = now - timedelta(days=self.MIN_HISTORY_DAYS)

            logs = (
                session.query(LogEvent)
                .filter(
                    LogEvent.asset_id == asset_id,
                    LogEvent.timestamp >= lookback_start,
                    LogEvent.timestamp <= lookback_end,
                )
                .all()
            )

            if len(logs) < 10:
                print(f"⚠️ Asset {asset.name}: Only {len(logs)} logs; skipping")
                return False

            print(f"📊 Asset {asset.name}: Analyzing {len(logs)} log events...")

            # Calculate hourly and daily patterns
            hourly_counts = self._calculate_hourly_pattern(logs)
            daily_counts = self._calculate_daily_pattern(logs)

            # Calculate overall statistics
            values = [len(logs_hour) for logs_hour in hourly_counts.values()]

            if not values:
                print(f"⚠️ Asset {asset.name}: No valid data; skipping")
                return False

            baseline_mean = mean(values)
            baseline_std = stdev(values) if len(values) > 1 else 0
            baseline_min = min(values)
            baseline_max = max(values)

            # Get of create baseline
            baseline = (
                session.query(AssetBehaviorBaseline)
                .filter_by(asset_id=asset_id)
                .first()
            )

            if baseline is None:
                baseline = AssetBehaviorBaseline(asset_id=asset_id)
                session.add(baseline)

            # Store baseline
            baseline.baseline_mean = baseline_mean
            baseline.baseline_std = max(baseline_std, 1.0)  # Avoid division by zero
            baseline.baseline_min = baseline_min
            baseline.baseline_max = baseline_max
            baseline.hourly_pattern = hourly_counts
            baseline.daily_pattern = daily_counts
            baseline.baseline_ready = True
            baseline.observations_count = len(logs)
            baseline.updated_at = now

            session.commit()

            print(f"   ✅ Mean: {baseline_mean:.1f}, StdDev: {baseline_std:.1f}")
            print(f"   ✅ Range: {baseline_min:.0f} - {baseline_max:.0f}")
            print(f"   ✅ Hourly pattern: {list(hourly_counts.keys())}")

            return True

        except Exception as e:
            print(f"❌ Error learning baseline for {asset.name}: {e}")
            session.rollback()
            return False

        finally:
            session.close()

    def _calculate_hourly_pattern(self, logs) -> Dict[int, float]:
        """Count average logs per hour (0-23)"""
        hourly = defaultdict(list)

        for log in logs:
            hour = log.timestamp.hour
            hourly[hour].append(log)

        # Average count per hour
        return {
            hour: len(logs) / (self.LEARNING_HISTORY_DAYS)
            for hour, logs in hourly.items()
        }

    def _calculate_daily_pattern(self, logs) -> Dict[int, float]:
        """Count average logs per day-of-week (0=Mon, 6=Sun)."""
        daily = defaultdict(list)

        for log in logs:
            day = log.timestamp.weekday()
            daily[day].append(log)

        # Average count per day
        days_observed = self.LEARNING_HISTORY_DAYS / 7
        return {day: len(logs) / days_observed for day, logs in daily.items()}
