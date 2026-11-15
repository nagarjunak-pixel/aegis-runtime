"""Stateful Enterprise ERP, Inventory ATP, Logistics, and Treasury subsystems with exact cents accounting."""

from __future__ import annotations

import random
import threading
from dataclasses import dataclass, field
from typing import Any

from pydantic import BaseModel, ConfigDict

from aegis.saga.coordinator import PermanentStepError, TransientStepError
from aegis.types import new_ulid_like


def _usd_to_cents(amount_usd: float) -> int:
    return int(round(amount_usd * 100))


def _cents_to_usd(cents: int) -> float:
    return round(cents / 100.0, 2)


@dataclass
class InventoryLot:
    sku: str
    plant: str
    total_physical_units: int
    available_atp_units: int
    reserved_units: int = 0
    row_version: int = 1


@dataclass
class CostCenterLedger:
    cost_center: str
    initial_allocation_cents: int
    available_cents: int
    encumbered_po_cents: int = 0
    settled_wire_cents: int = 0
    row_version: int = 1


@dataclass
class VendorRecord:
    vendor_id: str
    name: str
    country: str
    iban: str
    contact_email: str
    risk_tier: str = "LOW"


@dataclass
class CarrierLane:
    lane_id: str
    total_slots: int
    available_slots: int
    booked_slots: int = 0


@dataclass
class FaultProfile:
    """Deterministic or probabilistic chaos fault injection settings."""

    fail_tools_permanent: set[str] = field(default_factory=set)
    fail_tools_transient_once: set[str] = field(default_factory=set)
    random_transient_rate: float = 0.0
    random_permanent_rate: float = 0.0
    seed: int = 42


class InvariantAuditReport(BaseModel):
    """Mathematical conservation check across Inventory, Cost Centers, and Logistics."""

    model_config = ConfigDict(frozen=True)

    passed: bool
    violations: tuple[str, ...]
    total_allocated_usd: float
    total_available_usd: float
    total_encumbered_usd: float
    total_settled_usd: float
    active_reservations: int
    active_purchase_orders: int
    active_fx_hedges: int
    active_lane_bookings: int


class EnterpriseERPSandbox:
    """Thread-safe SAP S/4HANA-inspired ERP state machine enforcing conservation laws."""

    def __init__(self, fault_profile: FaultProfile | None = None) -> None:
        self._lock = threading.RLock()
        self._faults = fault_profile or FaultProfile()
        self._rng = random.Random(self._faults.seed)
        self._transient_triggered: set[str] = set()

        self._inventory: dict[tuple[str, str], InventoryLot] = {
            ("PLANT-DE-01", "MAT-CHIP-7NM"): InventoryLot(
                sku="MAT-CHIP-7NM",
                plant="PLANT-DE-01",
                total_physical_units=5_000,
                available_atp_units=5_000,
            ),
            ("PLANT-US-02", "MAT-HYD-VALVE"): InventoryLot(
                sku="MAT-HYD-VALVE",
                plant="PLANT-US-02",
                total_physical_units=2_500,
                available_atp_units=2_500,
            ),
            ("PLANT-SG-03", "MAT-LITH-CELL"): InventoryLot(
                sku="MAT-LITH-CELL",
                plant="PLANT-SG-03",
                total_physical_units=10_000,
                available_atp_units=10_000,
            ),
        }

        self._cost_centers: dict[str, CostCenterLedger] = {
            "CC-1000": CostCenterLedger(
                cost_center="CC-1000",
                initial_allocation_cents=500_000_000,  # $5,000,000.00
                available_cents=500_000_000,
            ),
            "CC-2000": CostCenterLedger(
                cost_center="CC-2000",
                initial_allocation_cents=200_000_000,  # $2,000,000.00
                available_cents=200_000_000,
            ),
        }

        self._vendors: dict[str, VendorRecord] = {
            "VEND-TSMC-01": VendorRecord(
                vendor_id="VEND-TSMC-01",
                name="Taiwan Semiconductor Precision Fab",
                country="TW",
                iban="DE89370400440532013000",
                contact_email="settlements@tsmc-partner.example.com",
            ),
            "VEND-BOSCH-02": VendorRecord(
                vendor_id="VEND-BOSCH-02",
                name="Bosch Rexroth Industrial Hydraulics",
                country="DE",
                iban="DE44500105175407324931",
                contact_email="ar-desk@rexroth-partner.example.com",
            ),
            "VEND-SANCTION-99": VendorRecord(
                vendor_id="VEND-SANCTION-99",
                name="Restricted Petrochem Trading Co",
                country="IR",
                iban="IR062960000000100324200001",
                contact_email="ops@restricted.example.org",
                risk_tier="SANCTIONED",
            ),
        }

        self._lanes: dict[str, CarrierLane] = {
            "LANE-AIR-TW-DE": CarrierLane(
                lane_id="LANE-AIR-TW-DE", total_slots=200, available_slots=200
            ),
            "LANE-AIR-DE-US": CarrierLane(
                lane_id="LANE-AIR-DE-US", total_slots=200, available_slots=200
            ),
        }

        self._reservations: dict[str, dict[str, Any]] = {}
        self._purchase_orders: dict[str, dict[str, Any]] = {}
        self._fx_hedges: dict[str, dict[str, Any]] = {}
        self._lane_bookings: dict[str, dict[str, Any]] = {}
        self._wires: dict[str, dict[str, Any]] = {}

    def set_fault_profile(self, profile: FaultProfile) -> None:
        with self._lock:
            self._faults = profile
            self._rng = random.Random(profile.seed)
            self._transient_triggered.clear()

    def get_vendor(self, vendor_id: str) -> VendorRecord:
        with self._lock:
            if vendor_id not in self._vendors:
                raise PermanentStepError(f"Unknown SAP vendor master '{vendor_id}'")
            return self._vendors[vendor_id]

    def _maybe_inject_fault(self, tool_name: str) -> None:
        if tool_name in self._faults.fail_tools_permanent:
            raise PermanentStepError(
                f"Downstream ERP/SWIFT gateway rejected '{tool_name}': HTTP 422 invariant fault"
            )
        if (
            tool_name in self._faults.fail_tools_transient_once
            and tool_name not in self._transient_triggered
        ):
            self._transient_triggered.add(tool_name)
            raise TransientStepError(
                f"SAP RFC gateway transient lock timeout on '{tool_name}' (HTTP 503)"
            )
        if self._faults.random_permanent_rate > 0.0 and (
            self._rng.random() < self._faults.random_permanent_rate
        ):
            raise PermanentStepError(f"Chaos injected permanent failure on '{tool_name}'")
        if self._faults.random_transient_rate > 0.0 and (
            self._rng.random() < self._faults.random_transient_rate
        ):
            raise TransientStepError(f"Chaos injected transient 503 on '{tool_name}'")

    async def reserve_atp(self, params: dict[str, Any], _prior: dict[str, Any]) -> dict[str, Any]:
        with self._lock:
            self._maybe_inject_fault("inventory.reserve_atp")
            plant = str(params["plant"])
            sku = str(params["sku"])
            qty = int(params["quantity"])
            if qty <= 0:
                raise PermanentStepError("Reservation quantity must be positive")
            lot = self._inventory.get((plant, sku))
            if lot is None:
                raise PermanentStepError(f"Material ({plant}, {sku}) not found")
            if lot.available_atp_units < qty:
                raise PermanentStepError(
                    f"Insufficient ATP for {sku}: requested {qty}, available {lot.available_atp_units}"
                )
            lot.available_atp_units -= qty
            lot.reserved_units += qty
            lot.row_version += 1
            res_id = new_ulid_like("resv")
            rec = {
                "reservation_id": res_id,
                "plant": plant,
                "sku": sku,
                "quantity": qty,
                "status": "ACTIVE",
                "row_version": lot.row_version,
            }
            self._reservations[res_id] = rec
            return dict(rec)

    async def release_atp(
        self, _params: dict[str, Any], forward_out: dict[str, Any]
    ) -> dict[str, Any]:
        with self._lock:
            res_id = str(forward_out["reservation_id"])
            rec = self._reservations.get(res_id)
            if rec is None or rec["status"] == "RELEASED":
                return {"reservation_id": res_id, "status": "ALREADY_RELEASED"}
            lot = self._inventory[(rec["plant"], rec["sku"])]
            qty = int(rec["quantity"])
            lot.reserved_units -= qty
            lot.available_atp_units += qty
            lot.row_version += 1
            rec["status"] = "RELEASED"
            return {"reservation_id": res_id, "released_units": qty, "status": "RELEASED"}

    async def create_purchase_order(
        self, params: dict[str, Any], _prior: dict[str, Any]
    ) -> dict[str, Any]:
        with self._lock:
            self._maybe_inject_fault("erp.create_purchase_order")
            cc_id = str(params.get("cost_center", "CC-1000"))
            vendor_id = str(params["vendor_id"])
            amount_cents = _usd_to_cents(float(params["amount_usd"]))
            if amount_cents <= 0:
                raise PermanentStepError("PO amount must be strictly positive")

            vendor = self.get_vendor(vendor_id)
            cc = self._cost_centers.get(cc_id)
            if cc is None:
                raise PermanentStepError(f"Unknown cost center '{cc_id}'")
            if cc.available_cents < amount_cents:
                raise PermanentStepError(
                    f"Insufficient budget in {cc_id}: needed {_cents_to_usd(amount_cents)}"
                )

            cc.available_cents -= amount_cents
            cc.encumbered_po_cents += amount_cents
            cc.row_version += 1

            po_id = new_ulid_like("po")
            po_rec = {
                "po_id": po_id,
                "cost_center": cc_id,
                "vendor_id": vendor_id,
                "vendor_country": vendor.country,
                "vendor_iban": vendor.iban,
                "vendor_email": vendor.contact_email,
                "amount_cents": amount_cents,
                "amount_usd": _cents_to_usd(amount_cents),
                "status": "ENCUMBERED",
            }
            self._purchase_orders[po_id] = po_rec
            return dict(po_rec)

    async def cancel_purchase_order(
        self, _params: dict[str, Any], forward_out: dict[str, Any]
    ) -> dict[str, Any]:
        with self._lock:
            po_id = str(forward_out["po_id"])
            po_rec = self._purchase_orders.get(po_id)
            if po_rec is None or po_rec["status"] == "CANCELLED":
                return {"po_id": po_id, "status": "ALREADY_CANCELLED"}
            cc = self._cost_centers[str(po_rec["cost_center"])]
            cents = int(po_rec["amount_cents"])
            if po_rec["status"] == "ENCUMBERED":
                cc.encumbered_po_cents -= cents
                cc.available_cents += cents
            elif po_rec["status"] == "SETTLED":
                cc.settled_wire_cents -= cents
                cc.available_cents += cents
            cc.row_version += 1
            po_rec["status"] = "CANCELLED"
            return {
                "po_id": po_id,
                "restored_usd": _cents_to_usd(cents),
                "status": "CANCELLED",
            }

    async def lock_fx_hedge(self, params: dict[str, Any], _prior: dict[str, Any]) -> dict[str, Any]:
        with self._lock:
            self._maybe_inject_fault("treasury.lock_fx_hedge")
            pair = str(params.get("currency_pair", "USD/EUR"))
            notional_usd = float(params["notional_usd"])
            hedge_id = new_ulid_like("fx")
            rec = {
                "hedge_id": hedge_id,
                "currency_pair": pair,
                "notional_usd": round(notional_usd, 2),
                "locked_rate": 0.9215 if pair == "USD/EUR" else 31.85,
                "status": "LOCKED",
            }
            self._fx_hedges[hedge_id] = rec
            return dict(rec)

    async def unwind_fx_hedge(
        self, _params: dict[str, Any], forward_out: dict[str, Any]
    ) -> dict[str, Any]:
        with self._lock:
            hedge_id = str(forward_out["hedge_id"])
            rec = self._fx_hedges.get(hedge_id)
            if rec is not None:
                rec["status"] = "UNWOUND"
            return {"hedge_id": hedge_id, "status": "UNWOUND"}

    async def book_expedited_lane(
        self, params: dict[str, Any], _prior: dict[str, Any]
    ) -> dict[str, Any]:
        with self._lock:
            self._maybe_inject_fault("logistics.book_expedited_lane")
            lane_id = str(params.get("lane_id", "LANE-AIR-TW-DE"))
            slots = int(params.get("slots", 1))
            lane = self._lanes.get(lane_id)
            if lane is None or lane.available_slots < slots:
                raise PermanentStepError(f"Insufficient air-freight capacity on {lane_id}")
            lane.available_slots -= slots
            lane.booked_slots += slots
            booking_id = new_ulid_like("ship")
            rec = {
                "booking_id": booking_id,
                "lane_id": lane_id,
                "slots": slots,
                "status": "BOOKED",
            }
            self._lane_bookings[booking_id] = rec
            return dict(rec)

    async def cancel_lane_booking(
        self, _params: dict[str, Any], forward_out: dict[str, Any]
    ) -> dict[str, Any]:
        with self._lock:
            booking_id = str(forward_out["booking_id"])
            rec = self._lane_bookings.get(booking_id)
            if rec is None or rec["status"] == "CANCELLED":
                return {"booking_id": booking_id, "status": "ALREADY_CANCELLED"}
            lane = self._lanes[str(rec["lane_id"])]
            slots = int(rec["slots"])
            lane.booked_slots -= slots
            lane.available_slots += slots
            rec["status"] = "CANCELLED"
            return {"booking_id": booking_id, "released_slots": slots, "status": "CANCELLED"}

    async def execute_wire(self, params: dict[str, Any], prior: dict[str, Any]) -> dict[str, Any]:
        with self._lock:
            self._maybe_inject_fault("treasury.execute_wire")
            po_step_key = str(params.get("po_step_ref", "create_po"))
            po_info = prior.get(po_step_key)
            po_id = str(params.get("po_id") or (po_info["po_id"] if po_info else ""))
            if not po_id or po_id not in self._purchase_orders:
                raise PermanentStepError(f"Wire transfer requires valid encumbered PO '{po_id}'")
            po_rec = self._purchase_orders[po_id]
            if po_rec["status"] != "ENCUMBERED":
                raise PermanentStepError(f"PO '{po_id}' is not in ENCUMBERED state")

            cc = self._cost_centers[str(po_rec["cost_center"])]
            cents = int(po_rec["amount_cents"])
            cc.encumbered_po_cents -= cents
            cc.settled_wire_cents += cents
            po_rec["status"] = "SETTLED"

            wire_id = new_ulid_like("wire")
            wire_rec = {
                "wire_id": wire_id,
                "po_id": po_id,
                "beneficiary_iban": str(params.get("beneficiary_iban", po_rec["vendor_iban"])),
                "amount_cents": cents,
                "amount_usd": _cents_to_usd(cents),
                "status": "SETTLED",
            }
            self._wires[wire_id] = wire_rec
            return dict(wire_rec)

    async def reverse_wire(
        self, _params: dict[str, Any], forward_out: dict[str, Any]
    ) -> dict[str, Any]:
        with self._lock:
            wire_id = str(forward_out["wire_id"])
            wire_rec = self._wires.get(wire_id)
            if wire_rec is None or wire_rec["status"] == "REVERSED":
                return {"wire_id": wire_id, "status": "ALREADY_REVERSED"}
            po_rec = self._purchase_orders[str(wire_rec["po_id"])]
            cc = self._cost_centers[str(po_rec["cost_center"])]
            cents = int(wire_rec["amount_cents"])
            cc.settled_wire_cents -= cents
            cc.encumbered_po_cents += cents
            po_rec["status"] = "ENCUMBERED"
            wire_rec["status"] = "REVERSED"
            return {"wire_id": wire_id, "status": "REVERSED"}

    async def update_vendor_iban(
        self, params: dict[str, Any], _prior: dict[str, Any]
    ) -> dict[str, Any]:
        with self._lock:
            self._maybe_inject_fault("vendor.update_bank_iban")
            vendor_id = str(params["vendor_id"])
            new_iban = str(params["new_iban"])
            vendor = self.get_vendor(vendor_id)
            old_iban = vendor.iban
            vendor.iban = new_iban
            return {"vendor_id": vendor_id, "previous_iban": old_iban, "new_iban": new_iban}

    def audit_conservation_invariants(self) -> InvariantAuditReport:
        """Verify mathematical conservation laws across all ERP tables."""
        with self._lock:
            violations: list[str] = []

            for (plant, sku), lot in self._inventory.items():
                if lot.available_atp_units < 0 or lot.reserved_units < 0:
                    violations.append(f"Negative inventory on ({plant}, {sku})")
                if lot.available_atp_units + lot.reserved_units != lot.total_physical_units:
                    violations.append(
                        f"Inventory conservation violated on ({plant}, {sku}): "
                        f"{lot.available_atp_units} + {lot.reserved_units} != {lot.total_physical_units}"
                    )

            total_alloc = 0
            total_avail = 0
            total_enc = 0
            total_set = 0
            for cc_id, cc in self._cost_centers.items():
                total_alloc += cc.initial_allocation_cents
                total_avail += cc.available_cents
                total_enc += cc.encumbered_po_cents
                total_set += cc.settled_wire_cents
                if (
                    cc.available_cents < 0
                    or cc.encumbered_po_cents < 0
                    or cc.settled_wire_cents < 0
                ):
                    violations.append(f"Negative balance in cost center {cc_id}")
                if (
                    cc.available_cents + cc.encumbered_po_cents + cc.settled_wire_cents
                    != cc.initial_allocation_cents
                ):
                    violations.append(
                        f"Double-entry conservation violated in {cc_id}: "
                        f"{cc.available_cents} + {cc.encumbered_po_cents} + {cc.settled_wire_cents} "
                        f"!= {cc.initial_allocation_cents}"
                    )

            for lane_id, lane in self._lanes.items():
                if lane.available_slots < 0 or lane.booked_slots < 0:
                    violations.append(f"Negative freight slots on {lane_id}")
                if lane.available_slots + lane.booked_slots != lane.total_slots:
                    violations.append(f"Freight slot conservation violated on {lane_id}")

            active_res = sum(1 for r in self._reservations.values() if r["status"] == "ACTIVE")
            active_pos = sum(
                1
                for p in self._purchase_orders.values()
                if p["status"] in ("ENCUMBERED", "SETTLED")
            )
            active_fx = sum(1 for h in self._fx_hedges.values() if h["status"] == "LOCKED")
            active_lanes = sum(1 for b in self._lane_bookings.values() if b["status"] == "BOOKED")

            return InvariantAuditReport(
                passed=len(violations) == 0,
                violations=tuple(violations),
                total_allocated_usd=_cents_to_usd(total_alloc),
                total_available_usd=_cents_to_usd(total_avail),
                total_encumbered_usd=_cents_to_usd(total_enc),
                total_settled_usd=_cents_to_usd(total_set),
                active_reservations=active_res,
                active_purchase_orders=active_pos,
                active_fx_hedges=active_fx,
                active_lane_bookings=active_lanes,
            )

    def state_summary(self) -> dict[str, Any]:
        with self._lock:
            return {
                "inventory": [
                    {
                        "plant": lot.plant,
                        "sku": lot.sku,
                        "total_units": lot.total_physical_units,
                        "available_atp": lot.available_atp_units,
                        "reserved": lot.reserved_units,
                        "version": lot.row_version,
                    }
                    for lot in self._inventory.values()
                ],
                "cost_centers": [
                    {
                        "cost_center": cc.cost_center,
                        "allocated_usd": _cents_to_usd(cc.initial_allocation_cents),
                        "available_usd": _cents_to_usd(cc.available_cents),
                        "encumbered_usd": _cents_to_usd(cc.encumbered_po_cents),
                        "settled_usd": _cents_to_usd(cc.settled_wire_cents),
                        "version": cc.row_version,
                    }
                    for cc in self._cost_centers.values()
                ],
                "lanes": [
                    {
                        "lane_id": ln.lane_id,
                        "total_slots": ln.total_slots,
                        "available_slots": ln.available_slots,
                        "booked_slots": ln.booked_slots,
                    }
                    for ln in self._lanes.values()
                ],
                "invariants": self.audit_conservation_invariants().model_dump(),
            }
