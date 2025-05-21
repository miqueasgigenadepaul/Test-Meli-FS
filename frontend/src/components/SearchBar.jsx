    import "./SearchBar.css"
    import icSearch from "../assets/ic_Search.png";
    import logoMeli from "../assets/Logo_ML.png"

    const SearchBar = ({input, handleInputChange, handleSearchClick}) => {
        return (
            <form className = "searchBar">
                    <img className = "logoMeli" src = {logoMeli} alt="Logo"/>
                    <input value = {input} onChange={handleInputChange} placeholder = "Nunca dejes de buscar"/>
                <div>
                    <button type = "submit" onClick={handleSearchClick} className = "icSearchButton">
                        <img className = "icSearch" src = {icSearch} />
                    </button>
                </div>
            </form> 
        )
    }

    export default SearchBar