```mermaid
erDiagram
    Role {
        UUID id PK
        string name "INVENTORY_MANAGER, PHARMACIST, etc."
        string description
    }

    User {
        UUID id PK
        string username
        UUID role_id FK
    }

    Store {
        UUID id PK
        string name
        string location_code
    }

    ProductCategory {
        UUID id PK
        string name
        string description
    }

    ProductMaster {
        UUID id PK
        string sku
        string name
        string form
        string strength
        UUID category_id FK
        string status
    }

    BinLocation {
        UUID id PK
        UUID store_id FK
        string bin_code
        string type "Fridge, CD_Cabinet, etc."
        integer capacity
    }

    BatchStock {
        UUID id PK
        UUID product_id FK
        string batch_no
        date expiry_date
        UUID store_id FK
        UUID bin_id FK
        decimal qty_on_hand
        decimal qty_reserved
        string status "Active, On_Hold, etc."
    }

    InventoryAdjustment {
        UUID id PK
        UUID product_id FK
        UUID batch_id FK "Nullable"
        UUID store_id FK
        decimal qty_delta
        string reason_code
        string status "Draft, Approved, etc."
        UUID requested_by_id FK
        UUID approved_by_id FK "Nullable"
    }

    ReconciliationSession {
        UUID id PK
        UUID store_id FK
        UUID started_by_id FK
        string status
        datetime started_at
    }

    ReconciliationCount {
        UUID id PK
        UUID session_id FK
        UUID product_id FK
        UUID batch_id FK
        decimal counted_qty
        decimal variance
    }

    InventoryAlert {
        UUID id PK
        UUID product_id FK
        UUID batch_id FK "Nullable"
        UUID store_id FK
        string type "Low_Stock, Expiring, etc."
        string status "Open, Acknowledged, etc."
        UUID assignee_id FK "Nullable"
    }

    CategoryThreshold {
        UUID id PK
        UUID store_id FK
        UUID category_id FK
        integer min_qty
        integer max_qty
        integer expiring_days
        integer unused_days
    }


    %% --- Relationships ---
    Role ||--|{ User : "is assigned to"
    User ||--|{ InventoryAdjustment : "requests/approves"
    User ||--|{ ReconciliationSession : "starts"
    User ||--o{ InventoryAlert : "is assigned to"
    Store ||--|{ BinLocation : "has"
    Store ||--|{ BatchStock : "contains"
    Store ||--|{ InventoryAdjustment : "occurs in"
    Store ||--|{ ReconciliationSession : "is for"
    Store ||--|{ InventoryAlert : "is raised for"
    Store |o--|{ CategoryThreshold : "has"
    ProductCategory ||--|{ ProductMaster : "categorizes"
    ProductCategory |o--|{ CategoryThreshold : "applies to"
    ProductMaster ||--|{ BatchStock : "has"
    ProductMaster ||--|{ InventoryAdjustment : "is for"
    ProductMaster ||--|{ ReconciliationCount : "is for"
    ProductMaster ||--|{ InventoryAlert : "is for"
    BinLocation ||--o{ BatchStock : "holds"
    BatchStock |o--|| InventoryAdjustment : "can be for"
    BatchStock |o--|| ReconciliationCount : "is for"
    BatchStock |o--|{ InventoryAlert : "can be for"
    ReconciliationSession ||--|{ ReconciliationCount : "contains"
