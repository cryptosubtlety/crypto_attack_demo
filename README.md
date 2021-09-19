**Warning**: the repository contains vulnerable code to demonstrate proof of concept attacks for educational purpose only. Do not use.

To reproduce BLS batch verify attacks (see [blog post](https://ethresear.ch/t/security-of-bls-batch-verification/10748))
```
git clone -n https://github.com/ethereum/py_ecc/
cd py_ecc && git checkout -b poc 59ad3d58dd97e31c3659ec08afc290f116515e1c
python3 -m venv ./venv && source venv/bin/activate && pip install . && cd ../
python3 ./bls_batchverify.py
```
