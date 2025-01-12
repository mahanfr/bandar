[![Contributors][contributors-shield]][contributors-url]
[![Forks][forks-shield]][forks-url]
[![Stargazers][stars-shield]][stars-url]
[![Issues][issues-shield]][issues-url]
[![MIT License][license-shield]][license-url]
[![LinkedIn][linkedin-shield]][linkedin-url]

# bandar

Open Source Container Engine.

Bandar is an open-source container engine designed to provide
a lightweight and efficient solution for containerization.
This project is written primarily in C and aims to deliver
a simple demenstration of docker style container managment.

## Installation

To install Bandar, follow these steps:

1. Clone the repository:

``` sh
git clone https://github.com/mahanfr/bandar.git
cd bandar
```

2. Build the project:

```sh
    make
```

## Usage

To use Bandar, follow these steps:

1. To Start the container engine:

``` sh
    ./build/bandar -u 0 -m . -c /bin/sh
```
options:

    -u  specify gid and uid
    -m  path to image
    -c  stating process of the container

## Contributing

We welcome contributions from the community.
To contribute, please follow these steps:

    Fork the repository.
    Create a new branch: git checkout -b my-feature-branch.
    Make your changes and commit them: git commit -m 'Add some feature'.
    Push to the branch: git push origin my-feature-branch.
    Create a pull request.

## License

This project is licensed under the MIT License.
See the LICENSE file for details.

[contributors-shield]: https://img.shields.io/github/contributors/mahanfr/bandar.svg?style=for-the-badge
[contributors-url]: https://github.com/mahanfr/bandar/graphs/contributors
[forks-shield]: https://img.shields.io/github/forks/mahanfr/bandar.svg?style=for-the-badge
[forks-url]: https://github.com/mahanfr/bandar/network/members
[stars-shield]: https://img.shields.io/github/stars/mahanfr/bandar.svg?style=for-the-badge
[stars-url]: https://github.com/mahanfr/bandar/stargazers
[issues-shield]: https://img.shields.io/github/issues/mahanfr/bandar.svg?style=for-the-badge
[issues-url]: https://github.com/mahanfr/bandar/issues
[license-shield]: https://img.shields.io/github/license/mahanfr/bandar.svg?style=for-the-badge
[license-url]: https://github.com/mahanfr/bandar/blob/master/LICENSE.txt
[linkedin-shield]: https://img.shields.io/badge/-LinkedIn-black.svg?style=for-the-badge&logo=linkedin&colorB=555
[linkedin-url]: https://linkedin.com/in/mahanfarzaneh
