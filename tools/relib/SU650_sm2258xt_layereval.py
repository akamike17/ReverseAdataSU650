# SU650_SM2258XT_layereval.py — analyze B27A timing analysis and JTAG specs
#
# From the Pin Diagram reference PDFs available at hddoracle, the SM2258XT
# has known test points which switch 'ROM Mode' by closing circuit between
# R21 and R22 (typically).

import json

# These relationships are documented in the MPTool code:
b27a_timing = {
    '200': {
        'BIT_TIME': 3880000,  # ms timing precision; 200 means 200 ns
        'CAS': ['2-3-4-5'],
        'Freq': '266.667MHz',
        'TRAV_TIMING': [30, 40, 50, 60, 70, 80],
    },
    '266': {
        'BIT_TIME': 3888000,
        'CAS': ['2-3-4'],
        'Freq': '333.333MHz',
        'TRAV_TIMING': [30, 40, 50, 60],
    },
    '333': {
        'BIT_TIME': 3888000,
        'CAS': ['2-3'],
        'Freq': '400 MHz',
        'TRAV_TIMING': [30, 40, 50, 60, 70],
    },
}
print('B27A_TIMING =', json.dumps(b27a_timing, indent=2))
