<div id="top"></div>

<!-- PROJECT SHIELDS -->
<!--
*** I'm using markdown "reference style" links for readability.
*** Reference links are enclosed in brackets [ ] instead of parentheses ( ).
*** See the bottom of this document for the declaration of the reference variables
*** for contributors-url, forks-url, etc. This is an optional, concise syntax you may use.
*** https://www.markdownguide.org/basic-syntax/#reference-style-links
-->
[![Contributors][contributors-shield]][contributors-url]
[![Forks][forks-shield]][forks-url]
[![Stargazers][stars-shield]][stars-url]
[![Issues][issues-shield]][issues-url]
[![MIT License][license-shield]][license-url]



<!-- PROJECT LOGO -->
<br />
<div align="center">
  <a href="https://github.com/SDMI-Developers/parsedan">
    <img src="https://raw.githubusercontent.com/SDMI-Developers/parsedan/master/assets/SDMI-Logo-Fullsize.png" alt="Logo" width="1000" height="178">
  </a>

<h3 align="center">Parsedan</h3>

  <p align="center">
    -
    <br />
    <a href="https://github.com/SDMI-Developers/parsedan/issues">Report Bug</a>
    ·
    <a href="https://github.com/SDMI-Developers/parsedan/issues">Request Feature</a>
  </p>
</div>



<!-- ABOUT THE PROJECT -->
## About The Project

<!-- [![Parsedan Screen Shot][product-screenshot]](https://example.com) -->
This project was writen to download data from shodan's api, parsing it, and scoring it. In its current state it uses a sqlite database to store objects. Every run of Parsedan will save to this database, so for example, you can run the program once a week and build a database of computers with scores for a given query.

If you simply want to run the script for a one time use, from a fresh database, run with the command --reset-db.

<p align="right">(<a href="#top">back to top</a>)</p>


<!-- GETTING STARTED -->
## Getting Started

### Prerequisites

This pacakge was built for python 3.6+.
* python 3.6+
  See [https://www.python.org/](https://www.python.org/)

### Installation
1. Install Parsedan
   ```sh
   pip install parsedan
   ```
2. Get a shodan API Key at [https://developer.shodan.io/api/requirements](https://developer.shodan.io/api/requirements)
3. Initalize parsedan with your key
   ```sh
   parsedan init API_KEY
   ```

<p align="right">(<a href="#top">back to top</a>)</p>



<!-- USAGE EXAMPLES -->
## Usage

WIP

<p align="right">(<a href="#top">back to top</a>)</p>


<!-- CONTRIBUTING -->
## Contributing

Contributions are what make the open source community such an amazing place to learn, inspire, and create. Any contributions you make are **greatly appreciated**.

If you have a suggestion that would make this better, please fork the repo and create a pull request. You can also simply open an issue with the tag "enhancement".
Don't forget to give the project a star! Thanks again!

1. Fork the Project
2. Create your Feature Branch (`git checkout -b feature/AmazingFeature`)
3. Commit your Changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the Branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

<p align="right">(<a href="#top">back to top</a>)</p>



<!-- LICENSE -->
## License

Distributed under the MIT License. See `LICENSE.txt` for more information.

<p align="right">(<a href="#top">back to top</a>)</p>



<!-- CONTACT -->
## Contact

Stephenson Disaster Management Institute at Louisiana State University - sdmidev@lsu.edu

Project Link: [https://github.com/SDMI-Developers/parsedan](https://github.com/SDMI-Developers/parsedan)

<p align="right">(<a href="#top">back to top</a>)</p>





<!-- MARKDOWN LINKS & IMAGES -->
<!-- https://www.markdownguide.org/basic-syntax/#reference-style-links -->
[contributors-shield]: https://img.shields.io/github/contributors/SDMI-Developers/parsedan.svg?style=for-the-badge
[contributors-url]: https://github.com/SDMI-Developers/parsedan/graphs/contributors
[forks-shield]: https://img.shields.io/github/forks/SDMI-Developers/parsedan.svg?style=for-the-badge
[forks-url]: https://github.com/SDMI-Developers/parsedan/network/members
[stars-shield]: https://img.shields.io/github/stars/SDMI-Developers/parsedan.svg?style=for-the-badge
[stars-url]: https://github.com/SDMI-Developers/parsedan/stargazers
[issues-shield]: https://img.shields.io/github/issues/SDMI-Developers/parsedan.svg?style=for-the-badge
[issues-url]: https://github.com/SDMI-Developers/parsedan/issues
[license-shield]: https://img.shields.io/github/license/SDMI-Developers/parsedan.svg?style=for-the-badge
[license-url]: https://github.com/SDMI-Developers/parsedan/blob/master/LICENSE.txt
[product-screenshot]: assets/example_run_1.png
