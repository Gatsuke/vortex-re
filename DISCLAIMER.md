# Responsible Use Disclaimer

Vortex-RE is a static analysis toolkit intended for software that **you own,
maintain, or are explicitly authorized to investigate**.

## Intended use

* Understanding how your own applications and their dependencies are built.
* Auditing software you are licensed to audit, where the license grants
  inspection rights.
* Security research conducted under responsible disclosure norms and within
  the scope of your authorization.
* Verifying what a build artifact actually contains before you ship it.

## Prohibited use

* Reverse engineering software you have no legal right to analyze.
* Circumventing technical protection measures, license enforcement, or
  DRM.
* Extracting credentials, personal data, or proprietary assets from
  artifacts you are not authorized to access.
* Any activity that violates applicable law or the terms under which you
  obtained the software.

## Technical scope

* Vortex-RE performs **static analysis only** in its current release: it
  does not execute, inject into, or observe the runtime behavior of
  inspected targets.
* Conclusions are evidence-backed but bounded by documented limitations;
  they do not constitute proof of runtime behavior or behavioral
  equivalence between artifacts.
* You are responsible for ensuring your use of this tool complies with the
  licenses and terms governing the software you inspect, and with the laws
  of your jurisdiction.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED. See [LICENSE](LICENSE) for the full license text.
