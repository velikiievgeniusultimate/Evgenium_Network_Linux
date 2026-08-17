# Plasma widget 0.2.7 load error

Observed on Plasma 6:

`Cannot assign to non-existent property "fullRepresentation"`

Cause: the 0.2.7 QML used the Plasma 5-style attached-property form `Plasmoid.fullRepresentation` even though the root object is a Plasma 6 `PlasmoidItem`. Plasma 6 exposes `fullRepresentation`, `preferredRepresentation`, and tooltip properties directly on `PlasmoidItem`.

Fixed in 0.2.8 by using the direct Plasma 6 properties.
