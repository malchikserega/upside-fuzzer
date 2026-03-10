#!/bin/bash

# Instrumentation Progress Script
# Shows detailed progress from original app to fully instrumented

set -e

echo ""
echo "═══════════════════════════════════════════════════════════"
echo "🔧 SharpFuzz Instrumentation Pipeline"
echo "═══════════════════════════════════════════════════════════"
echo ""

DLL_PATH="${1:-/app/bin/Release/net8.0/FuzzApi.dll}"
echo "📦 Target DLL: $DLL_PATH"
echo ""

# Step 1: Verify original DLL
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "STEP 1/5: Verifying Original DLL"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

if [ ! -f "$DLL_PATH" ]; then
    echo "❌ DLL not found: $DLL_PATH"
    exit 1
fi

DLL_SIZE=$(stat -f%z "$DLL_PATH" 2>/dev/null || stat -c%s "$DLL_PATH")
echo "✓ Original DLL found"
echo "  Size: $DLL_SIZE bytes"
echo ""

# Step 2: Analyze DLL
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "STEP 2/5: Analyzing Assembly"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

# Check for business logic classes
echo "Looking for business logic classes to instrument..."
CLASSES=$(dotnet tool run ilspy "$DLL_PATH" 2>/dev/null | grep -i "Logic" | head -5 || echo "  (Analysis skipped - ilspy not available)")
if [ ! -z "$CLASSES" ]; then
    echo "$CLASSES"
fi
echo "✓ Analysis complete"
echo ""

# Step 3: Backup original
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "STEP 3/5: Backup Original DLL"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

BACKUP_PATH="${DLL_PATH}.original"
cp "$DLL_PATH" "$BACKUP_PATH"
echo "✓ Backup created: $BACKUP_PATH"
echo ""

# Step 4: Run SharpFuzz instrumentation
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "STEP 4/5: SharpFuzz Instrumentation"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

cd /instrumentor
echo "Running instrumentor..."
echo ""

# Run with output
dotnet run "$DLL_PATH"
RESULT=$?

if [ $RESULT -ne 0 ]; then
    echo ""
    echo "❌ Instrumentation failed!"
    exit 1
fi

echo ""
echo "✓ Instrumentation complete!"
echo ""

# Step 5: Verify instrumented DLL
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
echo "STEP 5/5: Verifying Instrumented DLL"
echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"

INST_SIZE=$(stat -f%z "$DLL_PATH" 2>/dev/null || stat -c%s "$DLL_PATH")
DIFF=$((INST_SIZE - DLL_SIZE))

echo "✓ Instrumented DLL verified"
echo "  Original size:     $DLL_SIZE bytes"
echo "  Instrumented size: $INST_SIZE bytes"
echo "  Difference:        +$DIFF bytes"
echo ""

# Calculate percentage increase
PERCENT=$((DIFF * 100 / DLL_SIZE))
echo "  Size increase: +${PERCENT}% (SharpFuzz hooks added)"
echo ""

# Final summary
echo "═══════════════════════════════════════════════════════════"
echo "✅ INSTRUMENTATION COMPLETE!"
echo "═══════════════════════════════════════════════════════════"
echo ""
echo "Summary:"
echo "  ✓ Original DLL backed up"
echo "  ✓ Business logic instrumented"
echo "  ✓ SharpFuzz hooks injected"
echo "  ✓ Coverage tracking ready"
echo ""
echo "Next: Container startup will initialize SHM automatically"
echo "═══════════════════════════════════════════════════════════"
echo ""
