"""
Unit tests for Network Monitoring and Traffic Analysis Module
"""

import sys
import types

# Windows Application Control compatibility fix for scipy.spatial
if "scipy.spatial._ckdtree" not in sys.modules:
    try:
        import scipy.spatial._ckdtree  # noqa: F401
    except ImportError:
        dummy_ckdtree = types.ModuleType("scipy.spatial._ckdtree")
        dummy_ckdtree.cKDTree = object
        dummy_ckdtree.cKDTreeNode = object
        sys.modules["scipy.spatial._ckdtree"] = dummy_ckdtree
