using System;
using System.CommandLine;
using System.CommandLine.Parsing;
using System.Threading.Tasks;

namespace CheckCertificate
{
    internal class Program
    {
        /// <summary>
        /// The default port number to use.
        /// </summary>
        private const int PortNumberDefaultValue = 443;

        /// <summary>
        /// The minimum allowed value for the port number.
        /// </summary>
        private const int PortNumberMinimumValue = 1;

        /// <summary>
        /// The maximum allowed value for the port number.
        /// </summary>
        private const int PortNumberMaximumValue = 65535;

        /// <summary>
        /// The default number of days to warn before a certificate expires.
        /// </summary>
        private const int WarningDaysDefaultValue = 14;

        /// <summary>
        /// The minimum allowed value for warning days.
        /// </summary>
        private const int WarningDaysMinimumValue = 0;

        /// <summary>
        /// The maximum allowed value for warning days.
        /// </summary>
        private const int WarningDaysMaximumValue = 365;

        /// <summary>
        /// The default value of the skip chain validation.
        /// </summary>
        private const bool SkipChainValidationDefaultValue = false;

        /// <summary>
        /// Main entry point of the application.
        /// </summary>
        /// <param name="args">The command line arguments.</param>
        /// <returns>A return value indicating the result of the execution.</returns>
        static async Task<int> Main(string[] args)
        {
            ReturnValue returnValue = 0;

            // Argument: Host name
            var hostArgument = new Argument<string>
            (
                name: "host",
                description: "The hostname to connect to."
            );

            // Option: Port number
            var portOption = new Option<int>
            (
                name: "--port",
                description: "Override the port number to use.",
                getDefaultValue: () => PortNumberDefaultValue
            );

            // Validator for the port number
            portOption.AddValidator(ValidateOptionMinimumAndMaximum(portOption, PortNumberMinimumValue, PortNumberMaximumValue));

            //Option: Warning days
            var warningDaysOption = new Option<int>
            (
                name: "--warningdays",
                description: "Number of days to warn before certificate expires.",
                getDefaultValue: () => WarningDaysDefaultValue
            );

            // Validator for warning days
            portOption.AddValidator(ValidateOptionMinimumAndMaximum(warningDaysOption, WarningDaysMinimumValue, WarningDaysMaximumValue));

            // Options: skip chain validation
            var skipChainValidationOption = new Option<bool>
            (
                name: "--skip-chain-validation",
                description: "Skip checking of the entire certificate chain.",
                getDefaultValue: () => SkipChainValidationDefaultValue
            );

            // Create root command
            var rootCommand = new RootCommand
            {
                hostArgument,
                portOption,
                warningDaysOption,
                skipChainValidationOption
            };

            // Set handler and pass arguments and options
            rootCommand.SetHandler(async (context) =>
            {
                string hostName = context.ParseResult.GetValueForArgument(hostArgument);
                int portNumber = context.ParseResult.GetValueForOption(portOption);
                int warningDays = context.ParseResult.GetValueForOption<int>(warningDaysOption);
                bool skipChainValidation = context.ParseResult.GetValueForOption<bool>(skipChainValidationOption);

                var checker = new CertificateChecker();
                returnValue = await checker.Check(hostName, portNumber, warningDays, skipChainValidation, context.GetCancellationToken());
            });

            // Invoke handler
            await rootCommand.InvokeAsync(args);

            // Return the result
            return (int)returnValue;
        }

        /// <summary>
        /// Validate that the value of the <paramref name="option"/> is not lower than <paramref name="minimumValue"/> and not higher than <paramref name="maximumValue"/>.
        /// </summary>
        /// <param name="option">The option to check.</param>
        /// <param name="minimumValue">The minimum value to check for.</param>
        /// <param name="maximumValue">The maximum value to check for.</param>
        /// <returns></returns>
        private static ValidateSymbolResult<OptionResult> ValidateOptionMinimumAndMaximum(Option<int> option, int minimumValue, int maximumValue)
        {
            return result =>
            {
                // Get value for the option
                int value = result.GetValueForOption(option);

                // Make sure it's withing the boundaries, or else set error message
                if (value < minimumValue || value > maximumValue)
                {
                    result.ErrorMessage = $"The value of option '{option.Name}' must be between {minimumValue} and {maximumValue}.";
                }
            };
        }
    }
}
