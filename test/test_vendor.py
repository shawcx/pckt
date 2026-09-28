#!/usr/bin/env python3

import os
import unittest

import pckt
from pckt import vendor


class TestVendor(unittest.TestCase):
    def test_24_bit(self):
        self.assertEqual('VMware', vendor('00:50:56:00:aa:bb'))
        self.assertEqual('VMware', vendor(bytes.fromhex('000c29010203')))
        self.assertEqual('VMware, Inc.', vendor('00:50:56:00:aa:bb', full=True))

    def test_28_and_36_bit(self):
        # MA-M and MA-S blocks: the longest matching prefix wins over the parent OUI
        self.assertEqual('KoolPOS Inc.', vendor('00:55:da:12:34:56', full=True))
        self.assertEqual('OpenRB.com, Direct SIA', vendor('00:1b:c5:00:1a:bc', full=True))
        self.assertIsNone(vendor('00:1b:c5:ff:ff:ff'))

    def test_unknown(self):
        self.assertIsNone(vendor('02:00:00:00:00:01'))
        self.assertIsNone(vendor('ff:ff:ff:ff:ff:ff'))

    def test_every_entry_parses(self):
        with open(os.path.join(os.path.dirname(pckt.__file__), 'manuf'), encoding='utf-8') as f:
            entries = sum(1 for line in f if line.strip() and not line.startswith('#'))
        self.assertEqual(entries, sum(len(block) for block in pckt._manuf().values()))


if '__main__' == __name__:
    unittest.main()
