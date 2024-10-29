All models were validated against domain-network v6a6-1-2

small 2024-05-08 / 19

* Server -> Stores -> Data
* Impacts
  * loss of availability of Data is High (Medium in 2024-05-08 version)
* Control strategies
  * Embedded Host Security (Physical Device Protection @ Server)
  * Secure BIOS at Host (Secure BIOS @ Server)

small-uncontrolled

* Server -> Stores -> Data
* Impacts
  * loss of availability of Data is High (Medium in 2024-05-08 version)
* Control strategies
  * None

With the following 4 models we ideally should be reporting separately on the "ignore physical threats from world" control (see https://github.com/Spyderisk/domain-network/issues/156). Best to ignore them in the output for now.

small-1-secure-router.nq.gz
- two paths via routers from internet to data, one router has secure config, the other not
- shows the secure config on router1 as helping but states there are other higher likelihood paths
- shows uncontrolled causes
  - vulnerability in router 1 (i.e. getting through despite the secure config)
  - router2 being in service (an entirely uncontrolled path)

small-2-secure-router.nq.gz
- two paths via routers from internet to data, both routers have secure config
- shows both the secure configs as helping but states there are other higher likelihood paths
- shows uncontrolled causes
  - vulnerability in router 1 (i.e. getting through despite the secure config)
  - vulnerability in router 2 (i.e. getting through despite the secure config)

small-2-secure-router-1FW.nq.gz
- adds FWBlock at "[Interface:Router1-Internet]" ('block interface')
- shows 'Secure Host Config ("Router1")' as a "backstop" as the FW on router1 does the job upstream
- shows 'Secure Host Config ("Router2")' and the 'block interface' as helping but states there are other higher likelihood paths
- shows vulnerability discovery in router2 as uncontrolled cause

small-2-secure-router-2FW.nq.gz
- adds FWBlock at "[Interface:Router2-Internet]" ('block interface')
- shows both 'Secure host config' as backstops
- shows both 'block interface' as cause of reduction in likelihood
- shows no uncontrolled path

Steel Mill models
  - Models from the overview paper
  