# Tutorial (Windows)

1. First, download the required file from the Releases section.

    - ![Img1](./img/1.png)

    - ![Img2](./img/2.png)

2. Extract the downloaded ZIP file.

    - ![Img3](./img/3.png)

3. There is no need to modify the config file; simply run cf-scanner.exe.

4. The scanner output during scanning will look like this:

    - ![Img4](./img/4.png)
    - Green-colored logs indicate positive findings, which are written in the result.txt output file.
    - Yellow-colored logs indicate that the jitter level is higher than the specified value in the configuration.

5. Green results are recorded in the result.txt file.

    - ![Img5](./img/5.png)
    - ![Img6](./img/6.png)

## Important Notes

- You can exit the running scanner while still keeping the output stored in the result.exe file.
- The Goroutines option in the config file determines the number of simultaneous scans. Increasing this value results in faster scans but also increases the chance of delay error.
